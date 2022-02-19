import asyncio
import os
import sys
import json

from httpApi import httpApi

from typing import Optional

from nio import (AsyncClient, ClientConfig, DevicesError, Event, InviteEvent, LoginResponse, LocalProtocolError,
                 MatrixRoom, MatrixUser, RoomMessageText, crypto, exceptions, RoomSendResponse, PresenceSetError, PresenceSetResponse)

# This is a fully-documented example of how to do manual verification with nio,
# for when you already know the device IDs of the users you want to trust. If
# you want live verification using emojis, the process is more complicated and
# will be covered in another example.

# We're building on the restore_login example here to preserve device IDs and
# therefore preserve trust; if @bob trusts @alice's device ID ABC and @alice
# restarts this program, loading the same keys, @bob will preserve trust. If
# @alice logged in again @alice would have new keys and a device ID XYZ, and
# @bob wouldn't trust it.

# The store is where we want to place encryption details like our keys, trusted
# devices and blacklisted devices. Here we place it in the working directory,
# but if you deploy your program you might consider /var or /opt for storage
STORE_FOLDER = "settings/nio_store/"

# This file is for restoring login details after closing the program, so you
# can preserve your device ID. If @alice logged in every time instead, @bob
# would have to re-verify. See the restoring login example for more into.
SESSION_DETAILS_FILE = "settings/credentials.json"

# Only needed for this example, this is who @alice will securely
# communicate with. We need all the device IDs of this user so we can consider
# them "trusted". If an unknown device shows up (like @bob signs into their
# account on another device), this program will refuse to send a message in the
# room. Try it!
#file that contains Admin userid, Admin deviceids and Admin controll channel
ADMIN_FILE = "settings/admin.json"

# Json file that contains a userid like bridge@matrix.org and a homeserver like https://matrix.org
ACCOUNT_FILE = "settings/matrixaccount.json"
# Json file that is only used on first login if SESSION_DETAILS_FILE is not there,
# should only contain a pw key with the account pw as value.
# The file should be removed after first login, as its no longer needed
ONE_TIMEPASSWORD_FILE = "settings/pw.txt"


class CustomEncryptedClient(AsyncClient):
    def __init__(self, homeserver, user='', device_id='', store_path='', config=None, ssl=None, proxy=None):
        # Calling super.__init__ means we're running the __init__ method
        # defined in AsyncClient, which this class derives from. That does a
        # bunch of setup for us automatically
        super().__init__(homeserver,
                         user=user,
                         device_id=device_id,
                         store_path=store_path,
                         config=config,
                         ssl=ssl,
                         proxy=proxy)

        self.user_id = user
        # if the store location doesn't exist, we'll make it
        if store_path and not os.path.isdir(store_path):
            os.mkdir(store_path)

        #get admin values
        #should remove global var
        if os.path.exists(ADMIN_FILE) and os.path.isfile(ADMIN_FILE):
            try:
                with open(ADMIN_FILE, "r") as f:
                    admin = json.load(f)
                    self.admin_user_id = admin['user_id']
                    self.admin_device_ids = admin['device_ids']
                    self.admin_room_id = admin['room_id']

                    print(
                        f"Loaded admin details: {self.admin_user_id} on {self.admin_device_ids} in {self.admin_room_id}"
                    )

            except IOError as err:
                print(f"Couldn't load session from file. Logging in. Error: {err}")
                sys.exit(1)
            except json.JSONDecodeError:
                print("Couldn't read JSON file; overwriting")
                sys.exit(1)
        else:
            print("Could not load admin details")
            sys.exit(1)

        # invite callback
        self.add_event_callback(self.cb_autojoin_room, InviteEvent)

        # messages callback
        self.add_event_callback(self.cb_print_messages, RoomMessageText)

    async def login(self) -> str:
        """Log in either using the pw or (if possible) using the
        session details file.
        """
        # Restore the previous session if we can
        if os.path.exists(SESSION_DETAILS_FILE) and os.path.isfile(SESSION_DETAILS_FILE):
            try:
                with open(SESSION_DETAILS_FILE, "r") as f:
                    config = json.load(f)
                    self.access_token = config['access_token']
                    self.device_id = config['device_id']

                    # This loads our verified/blacklisted devices and our keys
                    self.load_store()
                    print(f"Logged in using stored credentials: {self.user_id} on {self.device_id}")

            except IOError as err:
                print(f"Couldn't load session from file. Logging in. Error: {err}")
            except json.JSONDecodeError:
                print("Couldn't read JSON file; overwriting")

        # We didn't restore a previous session, so we'll log in with a password
        if not self.access_token or not self.device_id:
            print("Using passwort for login")
            with open(ONE_TIMEPASSWORD_FILE, "r") as f:
                pw = f.readline().replace('\r', '').replace('\n', '')
                if len(pw) == 0:
                    print(f"Could not read 'pw' from {ONE_TIMEPASSWORD_FILE}: {pw}")
                    sys.exit(1)
                resp = await super().login(pw)
                if isinstance(resp, LoginResponse):
                    print("Logged in using a password; saving details to disk")
                    self.__write_details_to_disk(resp)
                else:
                    print(f"Failed to log in: {resp}")
                    sys.exit(1)
                return "pw"
        else:
            return "token"

    def trust_devices(self, user_id: str, device_list: Optional[str] = None) -> None:
        """Trusts the devices of a user.
        If no device_list is provided, all of the users devices are trusted. If
        one is provided, only the devices with IDs in that list are trusted.
        Arguments:
            user_id {str} -- the user ID whose devices should be trusted.
        Keyword Arguments:
            device_list {Optional[str]} -- The full list of device IDs to trust
                from that user (default: {None})
        """

        print(f"{user_id}'s device store: {self.device_store[user_id]}")

        # The device store contains a dictionary of device IDs and known
        # OlmDevices for all users that share a room with us, including us.

        # We can only run this after a first sync. We have to populate our
        # device store and that requires syncing with the server.
        for device_id, olm_device in self.device_store[user_id].items():
            if device_list and device_id not in device_list:
                # a list of trusted devices was provided, but this ID is not in
                # that list. That's an issue.
                print(f"Not trusting {device_id} as it's not in {user_id}'s pre-approved list.")
                continue

            if user_id == self.user_id and device_id == self.device_id:
                # We cannot explictly trust the device @alice is using
                continue

            self.verify_device(olm_device)
            print(f"Trusting {device_id} from user {user_id}")

    def add_trusted_device(self, user_id:str, device_id:str ) -> None:
        """ extend Trust to a certain device """
        for olm_device_id, olm_device in self.device_store[user_id].items():
            if device_id == olm_device_id:
                self.verify_device(olm_device)
                print(f"Trusting {device_id} from user {user_id}")


    def cb_autojoin_room(self, room: MatrixRoom, event: InviteEvent):
        """Callback to automatically joins a Matrix room on invite.
        Arguments:
            room {MatrixRoom} -- Provided by nio
            event {InviteEvent} -- Provided by nio
        """
        #self.join(room.room_id)
        #room = self.rooms[ROOM_ID]
        #print(f"Room {room.name} is encrypted: {room.encrypted}" )
        send_logMsg(f"i've been invited to {room.name}")

    async def cb_print_messages(self, room: MatrixRoom, event: RoomMessageText):
        """Callback to print all received messages to stdout.
        Arguments:
            room {MatrixRoom} -- Provided by nio
            event {RoomMessageText} -- Provided by nio
        """
        if event.decrypted:
            encrypted_symbol = "🛡 "
        else:
            encrypted_symbol = "⚠️ "
        print(f"{room.display_name} |{encrypted_symbol}| {room.user_name(event.sender)} ({event.sender}): {event.body}")

        if event.decrypted and event.verified and room.machine_name == self.admin_room_id \
         and event.sender == self.admin_user_id:
            print("- admin command")
            await self.parse_admin_command(event.body)

    async def parse_admin_command(self, body):
        """Parse comands send from admin account 
        Arguments:
            body {str} -- Comand (message) from admin account
        """
        if body == "exit":
            await self.send_logMsg("Shuting down")
            await self.shutdown()
            print("Stopping event loop ...")
            # Find all running tasks:
            pending = asyncio.all_tasks()
            for task in pending:
                task.cancel()
            print("tasks canceld")
        elif body.startswith("trust"):
            print("TODO extend Trust")
            dev_id = body.split(" ")
            if len(dev_id) == 2 and len(dev_id[1]) == 10:
                dev_id = dev_id[1]
                print("Add Trust to "+str(dev_id))
                self.add_trusted_device(self.admin_user_id, dev_id)
                await send_logMsg("Add Trusted device "+str(dev_id))
            #add_trusted_device
        elif body == "ping":
            await send_logMsg("pong")

    async def shutdown(self):
        print("shutdown")
        await client.set_presence("offline")


    async def send_logMsg(self, msg):
        """Sends message to admin_room_id
        Arguments:
            msg {str} -- Message that should be send
        """
        try:
            await self.room_send(room_id=self.admin_room_id,
                                 message_type="m.room.message",
                                 content={
                                     "msgtype": "m.text",
                                     "body": msg
                                 })
        except exceptions.OlmUnverifiedDeviceError as err:
            print("Encryption error")
            print("These are all known devices:")
            [print(f"\t{device.user_id}\t {device.device_id}\t {device.trust_state}\t  {device.display_name}") for device in self.device_store]
            await self.send_unverified_error()
            #sys.exit(1)

    async def send_unverified_error(self):
        try:
            await self.room_send(room_id=self.admin_room_id,
                                 message_type="m.room.message",
                                 content={
                                     "msgtype": "m.text",
                                     "body": "Error, unverified Devices"
                                 }, ignore_unverified_devices=True)
        except exceptions.OlmUnverifiedDeviceError as err:
            print("This should not happen")

    async def send_hello_world(self):
        """Sends message to admin_room_id to anounce beeing online
        """

        try:
            print("set presence")
            res = await self.set_presence("online")
            if isinstance(res, PresenceSetError):
                print("Could not set presence")
            elif isinstance(res, PresenceSetResponse):
                print("Success setting state")
            else:
                print("Unkown response state")
                print(res)

            await self.room_send(room_id=self.admin_room_id,
                                 message_type="m.room.message",
                                 content={
                                     "msgtype": "m.text",
                                     "body": "Hello, i'm online"
                                 })
        except exceptions.OlmUnverifiedDeviceError as err:
            print("OlmUnverifiedDeviceError")
            print("These are all known devices:")
            [print(f"\t{device.user_id}\t {device.device_id}\t {device.trust_state}\t  {device.display_name}") for device in self.device_store]
            #sys.exit(1)
            await self.send_unverified_error()

    @staticmethod
    def __write_details_to_disk(resp: LoginResponse) -> None:
        """Writes login details to disk so that we can restore our session later
        without logging in again and creating a new device ID.
        Arguments:
            resp {LoginResponse} -- the successful client login response.
        """
        with open(SESSION_DETAILS_FILE, "w") as f:
            json.dump({"access_token": resp.access_token, "device_id": resp.device_id, "user_id": resp.user_id}, f)


async def run_client(client: CustomEncryptedClient) -> None:
    """A basic encrypted chat application using nio.
    """

    # This is our own custom login function that looks for a pre-existing config
    # file and, if it exists, logs in using those details. Otherwise it will log
    # in using a password.
    login_type = await client.login()

    # Here we create a coroutine that we can call in asyncio.gather later,
    # along with sync_forever and any other API-related coroutines you'd like
    # to do.
    async def after_first_sync():
        # We'll wait for the first firing of 'synced' before trusting devices.
        # client.synced is an asyncio event that fires any time nio syncs. This
        # code doesn't run in a loop, so it only fires once
        print("Awaiting sync")
        await client.synced.wait()

        if login_type == "pw":
            # In practice, you want to have a list of previously-known device IDs
            # for each user you want ot trust. 
            client.trust_devices(client.admin_user_id, client.admin_device_ids)

            # In this case, we'll trust _all_ of @alice's devices. NOTE that this
            # is a SUPER BAD IDEA in practice, but for the purpose of this example
            # it'll be easier, since you may end up creating lots of sessions for
            # @alice as you play with the script
            client.trust_devices(client.user_id)

            await client.send_logMsg("Init trust (all on my account / configured ones on yours)")
        
        await client.send_hello_world()

    # We're creating Tasks here so that you could potentially write other
    # Python coroutines to do other work, like checking an API or using another
    # library. All of these Tasks will be run concurrently.
    # For more details, check out https://docs.python.org/3/library/asyncio-task.html

    # ensure_future() is for Python 3.5 and 3.6 compatability. For 3.7+, use
    # asyncio.create_task()
    after_first_sync_task = asyncio.ensure_future(after_first_sync())

    # We use full_state=True here to pull any room invites that occured or
    # messages sent in rooms _before_ this program connected to the
    # Matrix server
    sync_forever_task = asyncio.ensure_future(client.sync_forever(30000, full_state=True))

    await asyncio.gather(
        # The order here IS significant! You have to register the task to trust
        # devices FIRST since it awaits the first sync
        after_first_sync_task,
        sync_forever_task)


async def main():
    loop = asyncio.get_running_loop()
    # By setting `store_sync_tokens` to true, we'll save sync tokens to our
    # store every time we sync, thereby preventing reading old, previously read
    # events on each new sync.
    # For more info, check out https://matrix-nio.readthedocs.io/en/latest/nio.html#asyncclient
    config = ClientConfig(store_sync_tokens=True)
    # get user and homeserver from json file
    with open(ACCOUNT_FILE, "r") as f:
        matrixaccount = json.load(f)
        print("Load Account")
        print(matrixaccount)
        if not 'userid' in matrixaccount or not 'homeserver' in matrixaccount:
            print(f"Couldn't load 'userid' or 'homeserver' from {ACCOUNT_FILE} file. ")
            sys.exit(1)

        client = CustomEncryptedClient(
            matrixaccount['homeserver'],
            matrixaccount['userid'],
            store_path=STORE_FOLDER,
            config=config,
            #ssl=False,
            #proxy="http://localhost:8080",
        )

        print("=== Webserv ===")
        web = httpApi(client, loop)

        try:
            await run_client(client)
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass;
        finally:
            #shutdown the webserver
            web.stop()
            await client.close()


# Run the main coroutine, which instantiates our custom subclass, trusts all the
# devices, and syncs forever (or until your press Ctrl+C)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

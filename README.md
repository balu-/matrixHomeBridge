# matrixHomeBridge
Simple container that lets you send matrix messages via http post request


## Settings run this dockercontainer 
3 files in the `settings` folder are needed
- admin.json <br />
  Should contain a `user_id` field that names the owner of this Bridge,<br />
  a `device_ids` Array that lists all device ids whom the bridge trusts (for encryption)<br />
  a `room_id` field that lits the room id to which messages are posted <br />
- matrixaccount.json <br/>
  Should contain the account info the bridge is using<br />
  a `userid` filed that names the account the bridge uses<br />
  and a `homeserver` filed that names the matrix server to use <br />
- for the first run only pw.txt is need <br />
  Which contains only one line that contains the password of the account named in `matrixaccount.json`
- on first loggin credentials.json is created so that the pw.json file is no longer need

## Send a message
If the container is running, a simple http post request is enough to send a message

```
curl -X POST -i 'http://<dockerHostIP>:8080/notify' --data '{ "msg": "<THIS_IS_THE_MESSAGE>" }'
```

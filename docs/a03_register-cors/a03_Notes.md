

To make thiss a little more realistic, let's change the first client app and create two new client apps  
1, s03_register-cors-app where new app users will come to get a new key.  we don't need to ask for anything.  Just require an incomming AppID that get's sent to the register server which in turn sends back an app_key.
2. s04_customer1-app that has a link to the register app that contains the AppID.  The page also has a input field    



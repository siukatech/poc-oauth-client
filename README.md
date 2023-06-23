

# Reference
https://www.baeldung.com/?s=keycloak
https://www.baeldung.com/spring-boot-keycloak
https://www.baeldung.com/keycloak-oauth2-openid-swagger



# Error "finished with non-zero exit value 1"
Process 'command '/Library/Java/JavaVirtualMachines/jdk1.8.0_121.jdk/Contents/Home/bin/java'' finished with non-zero exit value 1  
https://noame123.medium.com/spring-boot-execute-error-finished-with-non-zero-exit-value-1-5e8317e6ad92


# Keycloak setup
https://keycloak.org/server/containers  

> docker run --name keycloak-server -p 38180:8080 \  
> -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=keycloak \  
> quay.io/keycloak/keycloak:21.1 \  
> start-dev

> login: admin  
> password: keycloak


# Keycloak Create New Realm
![Keycloak create realm after login as admin 01](./assets/keycloak-01-create-realm-01.png)
![Keycloak create realm 02](./assets/keycloak-01-create-realm-02.png)
![Keycloak create client 01](./assets/keycloak-02-create-client-01.png)
![Keycloak create client 02](./assets/keycloak-02-create-client-02.png)
![Keycloak create client 03](./assets/keycloak-02-create-client-03.png)
![Keycloak create client 04](./assets/keycloak-02-create-client-04.png)
![Keycloak setup client redirect-uri](./assets/keycloak-03-client-redirect-uri-01.png)
![Keycloak copy client secret 01](./assets/keycloak-04-client-secret-01.png)




# Postman Working Offline  
Click setting and then select "Scratch Pad"  
![Scratch Pad](./assets/postman-01-scratch-pad-01.png)


# Postman Keycloak openid-configuration
According to the version of keycloak after "v 17.0 and newer"  
The url of openid-configuration api has been changed, "/auth" is removed   
__From:__ {{server}}/auth/realms/{{realm}}/.well-known/openid-configuration
__To:__ {{server}}/realms/{{realm}}/.well-known/openid-configuration
https://www.baeldung.com/postman-keycloak-endpoints

__api:__ {{idp-server}}/realms/{{client-realm}}/.well-known/openid-configuration  
![Check openid-configuration](./assets/postman-04-openid-configuration-01.png)


# Postman Environment Variables Setup for Keycloak
environment variables preparation  
> __app-server:__ http://localhost:28080  
> __client-id:__ react-backend-client-01  
> __client-secret:__ ${client-secret}  
> __client-realm:__ react-backend-realm  
> __idp-server:__ http://localhost:38180  
> __idp-redirect_uri:__ {{app-server}}/v1/public/authorized  
> __idp-auth-url:__ {{idp-server}}/realms/{{client-realm}}/protocol/openid-connect/auth  
> __idp-access-token-url:__ {{idp-server}}/realms/{{client-realm}}/protocol/openid-connect/token

![Postman environment setup 01](./assets/postman-02-environment-setup-01.png)  



# Postman collection auth setup
> __token name:__ access_token  
> __grant type:__ Authorization Code  
> __callback url:__ {{idp-redirect_uri}}  
> __auth url:__ {{idp-auth-url}}  
> __access token url:__ {{idp-access-token-url}}  
> __client id:__ {{client-id}}  
> __client secret:__ {{client-secret}}  

![Postman collection auth 01](./assets/postman-03-collection-auth-01.png)  



# Keycloak export and import
## Reference
https://howtodoinjava.com/devops/keycloak-export-import-realm/
https://howtodoinjava.com/devops/keycloak-script-upload-is-disabled/


## Preparation
Remove the "authorizationSettings" block in the *realm.json files
![Remove authorizationSettings in json](./assets/keycloak-07-remove-authorizationSettings-01.png)


## Export
docker ps -a
docker exec -it [container-id] bash
> ###example  
> docker exec -it e5c79daf5235 bash

execute export commands
> cd /opt/keycloak  
> ###including both realm and users data  
> ###./kc.sh export --dir /tmp/keycloak-all-data-[yyyyMMdd]-[hh:mm]  
> ./kc.sh export --dir /tmp/keycloak-all-data-20230623-1020  
> exit  

![kc.sh export ...](./assets/keycloak-05-export-01-by-bash-01.png)


docker cp [container-id]:/tmp/keycloak-all-data-[yyyyMMdd]-[hh:mm] /local-somewhere-eg-tmp/
> docker cp e5c79daf5235:/tmp/keycloak-all-data-20230623-1145 ~/Documents/development/artifact/keycloak/data-20230623-1145  

![docker cp ...](./assets/keycloak-05-export-01-by-bash-02.png)


## Import
Need to create the realm and import users manually with exported files  
![Create a new realm with json file 01](./assets/keycloak-06-import-01-create-realm-with-json-01.png)
![Create a new realm with json file 02](./assets/keycloak-06-import-01-create-realm-with-json-02.png)
![Create a new realm with json file 03](./assets/keycloak-06-import-01-create-realm-with-json-03.png)
![Import users 01](./assets/keycloak-06-import-02-import-users-by-json-01.png)
![Import users 02](./assets/keycloak-06-import-02-import-users-by-json-02.png)
![Import users 03](./assets/keycloak-06-import-02-import-users-by-json-03.png)
![Import users 04](./assets/keycloak-06-import-02-import-users-by-json-04.png)
![Import users 05](./assets/keycloak-06-import-02-import-users-by-json-05.png)
![Import users 06](./assets/keycloak-06-import-02-import-users-by-json-06.png)



# gradle:bootRun Setup
Prepare the following environment variables for bootRun
client-id=[client-id];client-realm=[client-realm];oauth2.client.keycloak=[keycloak-host];spring.profiles.active=[spring profile];client-secret=[client-secret]  
> client-id=oauth-client-01;client-realm=oauth-client-realm;oauth2.client.keycloak=http://localhost:38180;spring.profiles.active=dev;client-secret=XXX



# MC.Auth
An Orchard CMS module that replaces authentication of users to use Identity Server. Please be aware that this is a prototype and will require some significant modification before it can be used in production.

There are some modifications you will have to make in OwinMiddlewares.cs in order to make this work for your scenario. Here is what I can remember...

1. You will need to install Identity Server and ensure it is available at the https://localhost:44333/core.
2. You will need to update the redirect URL to that of your application.
3. You will need to update the katanaclient config in IdSrv host.

This module was built using the Identity Server sample host (SelfHost although you should probably use the Web host).
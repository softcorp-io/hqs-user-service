# HQS User Service

## Overview

HQS User Service is a microservice part of the HQS Platform. The service is respnsible for creating, updating, deleting and validating users. It's build using an GRPC architecture and uses a Mongo database for storing users and tracking & blocking JWT tokens as well as storing a history of login attempts. For storage, we currently use DigitalOcean Spaces, but are looking to move to Caddy or Nginx. We'we made a few speed tests, which you can find under expiriments. The service is tested on a macbook pro with 16 gb of ram and a quad core i7 proccessor. 


## Functions
| Function            | Description                              |
| ------------------- | ---------------------------------------- |
| Create              | Create a user                            |
| GenerateSignupToken | Generates special signup token           |
| Signup              | Signup given a jwt token                 |
| Get                 | Get a user by its id                     |
| GetByToken          | Get a user by JWT                        |
| GetByEmail          | Get single user by email                 |
| GetAll              | Get all users                            |
| Delete              | Delete a user                            |
| UpdateProfile       | Update a users profile                   |
| UpdateAllowances    | Update a users allowances                |
| UpdatePassword      | Update a users password                  |
| UpdateBlockUser     | Block or unblock a user                  |
| Auth                | Authenicate                              |
| ValidateToken       | Validate a JWT token                     |
| BlockToken          | Block a JWT token by providing the token |
| BlockTokenByID      | Block a token by its uuid                |
| BlockUsersTokens    | Block all users tokens                   |
| GetAuthHistory      | Get the login history                    |
| UploadImage         | Uploads a new user image                 |

## Configure
The service is configured by parsing or providing an ```hqs.env``` file, containing the following values:

| Name                      | Value                                                        |
| ------------------------- | ------------------------------------------------------------ |
| MONGO_HOST                | A host for the mongo database                                |
| MONGO_USER                | A user for the mongo database                                |
| MONGO_PASSWORD            | A password for the mongo database                            |
| MONGO_DBNAME              | A database name for the mongo database                       |
| MONGO_DB_USER_COLLECTION  | A name for the user collection in mongo                      |
| MONGO_DB_AUTH_COLLECTION  | A name for the auth collection in mongo                      |
| MONGO_DB_TOKEN_COLLECTION | A name for the token collection in mongo                     |
| CRYPTO_JWT_KEY            | A secret key for JWT tokens                                  |
| AUTH_HISTORY_TTL          | A time, eg. "168h", specifing how long the auth history is kept alive |
| TOKEN_TTL                 | A time, eg. "168h", specifing how long the token is kept alive |
| SPACES_KEY                | Spaces key for storage (digital ocean spaces)                |
| SPACES_SECRET             | Spaces secret key for storage (digital ocean spaces)         |
| SPACES_REGION             | Spaces region (digital ocean spaces)                         |
| SPACES_ENDPOINT           | Spaces endpoint (digital ocean spaces)                       |
| SERVICE_PORT              | What port the service should run on                          |

## How to run

After configuring the enviroment, you can simply run the service by running ```go run main.go```.


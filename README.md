# High-Dependable-System

## Instructions

For pratical purposes, there will be set in folder a executable for running the whole application.
It is important to know that the file simulate.txt will set the behaviour of this application.

You can change this behaviour following this form:

In the beggining of the file should always be set as follows:

```
f,[number of byzantine users]
u,[number of users]
ha,[number of healthcare authorities]
user[x],b
user[y],b
user[z],b
  ... -> as many declarations as f is settled
setupclients
```

Note that, user[x], where **x** should be a number from 1 to **u**, define the byzantine users in the System.
The should only be **f** declarations of these byzantine users.
The instruction **setupclients** starts running clients into the apllication and verifying connections.

***IMPORTANT: The past instructions should always be declarad as stated. See the example***

Example of a simulate.txt:
```
f,5
c,10
ha,1
user2,b
user4,b
user6,b
user8,b
user10,b
setupclients
```

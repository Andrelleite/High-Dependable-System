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
  ... -> runtime instructions
endsim
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
  ...
endsim
```

Following this lines, should be set the instructions for runtime.
This instructions are different for pratical reasons and we will define them for the following lines:
1.generateproof,[epoch] : To generate the proofs of location for all the clients in the system. Epoch should be defined between 1 and the last epoch defined in the grid.txt;
2.fake,[epoch],user[x],user[y] : To try to fake a proof, where user[x] will try to fake his identity as user[y];
3.user[x],request,[epoch] : User request of his location proofs at epoch [epoch];
4.ha,user[x],[epoch] : Health Authority generates a request for location proof of user[x] at epoch [epoch];
5.ha,position,x,y,[epoch] : Health Authority generates a request for all location proof located at (x,y) at the instance [epoch];
6.server,[down|up] : Simulates Server crash or forced drop. **down** simulates the connection fault, **up** reconnects the server;





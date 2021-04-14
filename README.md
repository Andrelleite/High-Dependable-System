# High-Dependable-System

## Test files Setup

Firstly there is defined the file **grid.txt**, where all moves are depicted. This files sets the first epoch and last, as well as the locations for each client at each of these epochs.
This file follows a simple type of definitions, such as the next example:

```
user2, 0, 30, 30
user3, 0, 10, 15
user4, 0, 30, 37
user5, 0, 30, 37
user6, 0, 30, 37
user7, 0, 30, 37
user8, 0, 30, 37
user9, 0, 30, 37
user1, 1, 10, 20
user2, 1, 30, 30
user3, 1, 10, 15
user4, 1, 30, 37
user5, 1, 30, 37
user1, 2, 10, 20
user2, 2, 30, 30
user3, 2, 10, 15
user4, 2, 30, 37
```

It is important to know that the file **simulate.txt** will set the behaviour of this application.
You can change this behaviour following this file type of construct.
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
1. **generateproof,[epoch]** : To generate the proofs of location for all the clients in the system. Epoch should be defined between 1 and the last epoch defined in the grid.txt;
2. **fake,[epoch],user[x],user[y]** : To try to fake a proof, where user[x] will try to fake his identity as user[y];
3. **user[x],request,[epoch]** : User request of his location proofs at epoch [epoch];
4. **ha,user[x],[epoch]** : Health Authority generates a request for location proof of user[x] at epoch [epoch];
5. **ha,position,x,y,[epoch]** : Health Authority generates a request for all location proof located at (x,y) at the instance [epoch];
6. **server,[down|up]** : Simulates Server crash or forced drop. **down** simulates the connection fault, **up** reconnects the server;
7. **spy,registry,user[x],user[y]** : TO BE DETERMINED
8. **spy,reports,user[x],user[y]** : TO BE DETERMINED


## Running Files



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

***NOTE: Make sure all users have defined locations, even though they are stationary. ***

It is important to know that the file **simulate.txt** will set the behaviour of this application.
You can change this behaviour following this file type of construct.
In the beggining of the file should always be set as follows:

```
f,[number of byzantine users],[f line < f]
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
7. **spy,reports,user[x],user[y]** : Simulates a byzantine user trying to access other user reports;

## Output Files

  All outputs generated will be stored at files regarding every instance in the application. 
  For the purpose of organized information and readable content, they are created at the start of each of this instances and are not final. It's just expected the changes to persist until the next application run.
  They are located at this directory:
  
  -> **C:\...\High-Dependable-System\output\ ...**

## Running Files

To easily run the application, first make sure you followed the next Steps:

1. Setup file **grid.txt** with all moves to perform;
2. Setup file **simulate.txt** or select on from the existent;
3. Run **Application.java**
4. Select a number, indicating the simulation to run;
5. Check the outputs at */outputs*;

```

```

## Expected Outputs

Within, there's a set of simulations to be carried out. There's no need of creating any grid files to go with them, since the simulator already takes take job in creating a random grid instance for the simulation file choosen. 

There will be five simulations, all of them with the according grid files.

These have intrisic objectives:

1. **Simulation1.txt** : This simulation is the simplest one as it only performs the proof generation for all of the epochs. The output for this file should focus the Server and the Clients. For this reason, files **Server.txt** and **User[x].txt** are created at /output. In the server should be the requests for each client and the proof with all it's segments. In the client should be presented the request made, but no definition of proof.
2. **Simulation2.txt** : In this simulation, it's expected some request of reports made for some clients, and so, it's important to verifiy that their reports show on the according files. Also, some byzantine behaviour is set, and for that, files of this kind of users should be very similar with the clients, BUT, with the fact that no request is correct or accepet, showing errors and denials.
3. **Simulation3.txt** : In this particular simulation, even as it's made all operations as before, it's added the Healthcare Authority. The HA will make two types of request, one for a specific location at an epoch, and another for a user at an epoch. But, all this will happen when the server has crashed. So, it's interesting to check the behaviour of the HA when this drop happens and how he handles it. Futhermore, in **HA.txt** should also be both requests anwsered.
4. **Simulation4.txt** : This simulation is a more accute version of simulation3.txt, and for that reason all files according to the users operating should present changes, as well the server and HA.
5. **Simulation5.txt** : This simulation takes us to the pinacle of protection in the system. In this particular set of operations, there will only be performed Byzantine behaviours. Furthermore, in Server.txt should be present the request and their denials. In the user file, there will be no concrete data, only information regarding when the request was made and which one, since according to our protection settings, these clients have no capacity of decoding information of another.
 
  

Thank you for your time and attention. That's enough for this to go smoothly.

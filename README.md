# High-Dependable-System

## Test Files

   To find the test files and scripts go to **/High-Dependable-System-main/src/grid**

## Test files Setup

First of all, there are the files of the type **grid.txt**, where all moves are depicted. This files sets the first epoch and last, as well as the locations for each client at all epochs.
This file follows a simple structure, such as the next example:

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

It is important to know that the files **simulate.txt** will set the behaviour of this application.
You can change this behaviour following this file type of construct.
The beggining of the file should always be set as follows:

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

***IMPORTANT: The former instructions should always be declarad as stated. See the example***

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

Following the former example, it should set the basic instructions for run time (where the ellipsis are positioned), now we can choose which actions to perform in the simulation.
These instructions are different for pratical reasons and we will define them for the following lines:
1. **generateproof,[epoch]** : To generate the proofs of location for all the clients in the system. Epoch should be defined between 1 and the last epoch defined in the grid.txt;
2. **fake,[epoch],user[x],user[y]** : To try to fake a proof, where user[x] will try to fake his identity as user[y];
3. **user[x],request,[epoch]** : User request of his location proofs at epoch [epoch];
4. **ha,[ha_ID],user[x],[epoch]** : Health Authority generates a request for location proof of user[x] at epoch [epoch];
5. **ha,[ha_ID],position,x,y,[epoch]** : Health Authority generates a request for all location proof located at (x,y) at the instance [epoch];
6. **server,[down|up],[server_ID]** : Simulates Server crash or forced drop. **down** simulates the connection fault, **up** reconnects the server;
7. **spy,reports,user[x],user[y]** : Simulates a byzantine user trying to access other user reports;

## Output Files

  All outputs generated will be stored in files regarding every instance in the application. 
  For the purpose of organized information and readable content, they are created at the start of each of this instances and are not final. It's expected the changes to persist until the next application run.
  They are located at this directory:
  
  -> **C:/.../High-Dependable-System/output/ ...**

## Running Files

To compile and run the project we used IntelliJ, a Java IDE, with JDK 15, we suggest the use of this setup to facilitate running the project. 
To easily run the application, first make sure you follow the next steps on the IDE:

1. Setup file **simulate.txt** or select on from the existent;
2. Run **Application.java** on IntelliJ
3. Select a number, indicating the simulation to run on the IDE console;
4. Check the outputs at */outputs*;

Note that at runtime, an input will be requested regarding which simulation to follow.
Please check out first which simulate files are available, and select a correct number.
As this is set, the simulation will present the number of users, the total of byzantine users and those around another users.

This example performs **Simulation1.txt**, as input = **1**:
```
NUMBER OF SIMULATION: 1 
NUMBER OF USERS: 5
====================== SIMULATION HAS STARTED ======================
F: 2 F': 1
```

***NOTE: DO NOT FIDDLE WITH ClientReports.txt and SystemUsers***

## Expected Outputs

Within the project, there's a set of simulations to be carried out. There's no need of creating any grid files to go with them, since the simulator already creates a random grid instance for the simulation file chosen. 

There will be five simulations files, all of them with their according grid files.

These have intrisic objectives:

1. **Simulation1.txt** : This simulation is the simplest one as it only performs the proof generation for all of the epochs. The output for this file should focus the Server and the Clients. For this reason, files **Server.txt** and **User[x].txt** are created at /output. In the server should be the requests for each client and the proof with all its segments. In the client it should be presented the requests made for the proof generation, but no reports of the proof sent to the server (since it only appears when a user requests it to the server).
2. **Simulation2.txt** : In this simulation, are expected some requests of reports made for some clients, and so, it's important to verifiy that their reports show on the according files. Also, some byzantine behaviour is set, and for that, files of this kind of users should be very similar with the clients, however, with the difference that no request is correct or accepted, showing errors and server denials.
3. **Simulation3.txt** : In this particular simulation, despite being made the same operations as before, it's added the Healthcare Authority. The HA will make two types of request, one for a specific location at an epoch, and another for a user at an epoch. But, all this will happen when the server has crashed. So, it's interesting to check the behaviour of the HA when this drop happens and how he handles it and still gets the requests made to the server. Futhermore, in the **HA.txt** should also be displayed both requests and its answers.
4. **Simulation4.txt** : This simulation is a more acute version of simulation3.txt, and for that reason all files regarding to the users operations should present changes regarding to the responses of those said operations, as well as both the server and HA files.
5. **Simulation5.txt** : This simulation takes us to the pinacle of protection in the system. In this particular set of operations, there will only be performed Byzantine behaviours. In Server.txt should be present the requests made and their denials. In the users' files, there will be no concrete data, only information regarding when the request was made and which one, since according to our protection settings, these clients can not request the data of another user, so all the requests will be denied by the server.
 
  

Thank you for your time and attention. That's enough for this to go smoothly.

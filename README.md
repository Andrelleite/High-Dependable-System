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
REPLICAS: 7
```

***NOTE: DO NOT FIDDLE WITH ClientReports.txt and SystemUsers***

## Expected Outputs

Within the project, there's a set of simulations to be carried out. There's no need of creating any grid files to go with them, since the simulator already creates a random grid instance for the simulation file chosen. 

There will be five simulations files, all of them with their according grid files.

These have intrisic objectives:

1. **Simulation1.txt** : Validation of multiple Health Care Authorities request to the network. Multiple files should be created to state the replies from the servers.
2. **Simulation2.txt** : Simple users requests to the network. Interesting to test the Atomicity of the registers.
3. **Simulation3.txt** : Introduction to byzantine behaviour on the client side of the application.
4. **Simulation4.txt** : Close to reality simulation, with byzantine behaviour as well as server crash during runtime.
5. **Simulation5.txt** : Fully Byzantine simulation.
6. **Simulation6.txt** : Clean report generation in all epochs. 
7. **Simulation7.txt** : Clients request to their witnessed reports, with some HA activity. **NEW METHOD**
  

Thank you for your time and attention. That's enough for this to go smoothly.

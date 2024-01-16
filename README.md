# YarWeb
<h2>How to use YarWeb: </h2>
<h3>Python script:</h3>
<p>final.py is the heart of YarWeb. It does all the backend and core functions including- concatenating strings, removing duplicates, formatting the subset into a YARA rule, testing the YARA rule using yara-python, storing user information, hashing the credentials, updating the YARA rule, conducting a succinct login process, and use third-party vendor support for malware scanning. 

These Python packages are to be installed on the host device:
<p align="center">
<img src="![Screenshot 2024-01-16 175228](https://github.com/Laalas333/YarWeb/assets/141653171/720f900d-2d9c-47ac-a40c-d0a46e784880)
" height="80%" width="80%"><br>
Fig 1.1<br></p>
</p>

<h3>File setup:</h3>
<p> 6 folders are to be available in the current working directory for YarWeb to function. These folders will be explained individually below:
<p align="center">
<img src="![Screenshot 2024-01-16 175259](https://github.com/Laalas333/YarWeb/assets/141653171/de0f3a26-606d-4374-82cc-88679fbc13aa)
" height="80%" width="80%"><br>
Fig 1.2<br></p>
<b>Instance</b> is a folder created by the script in association with the SQLAlchemy package. The purpose of this directory is to store a users.db file. This database file contains all the login information about the users who have registered on YarWeb. It is to be noted, that all the user-sensitive information such as passwords are encrypted/hashed before being stored in the database using the Python package bcyrpt.<br>

<b>test_malwares</b> is a folder that contains all the malware signature folders. Subsequently, these signature folders store malware samples of their own. These files are used to create the .csv files i.e. the database for rule creation.<br>

<b>temp</b> is a folder that stores data only temporarily. This is primarily used whenever the user/admin has to perform an upload function. When the data is uploaded, it is stored in the temp folder for a short amount of time. When the task is completed, the file is automatically deleted from the folder.<br>

<b>templates</b> this folder holds all the necessary HTML files for the front end of YarWeb. <br>

<b>yara_files</b> is a folder that stores all the YARA rules produced from the interaction. The Python script ensures that if multiple users were to work on the same malware signature, only one YARA rule is stored in the directory. This is done to reduce duplicates and redundant YARA rules. Moreover, this directory is called upon at the time of rule updation. Strings from the user are concatenated to the chosen rule present in the directory, which successfully updates it.<br>

<b>Malware_for_testing</b> is a folder that contains signature folders very similar to test_malwares folder. However, the malware samples included here are purely for testing purposes and are not used for the creation of the database. In YarWeb when the user is led to the testing stage, the user can use samples from these signature folders. However, it is not limited to only these test samples. 

Make sure that the .csv databases are not stored together in a folder of their own. If done so, changes would have to be made to the final.py script. The Python script should also be in the current working directory but not in a separate folder within the directory. An ideal setup would look like this:

<p align="center">
<img src="![Screenshot 2024-01-16 175356](https://github.com/Laalas333/YarWeb/assets/141653171/eed2823e-e23a-49cb-9ed3-5d89b4c98609)
" height="80%" width="80%"><br>
Fig 1.3<br></p>
</p>

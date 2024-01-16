# YarWeb
# How to use YarWeb:
# Python script:
final.py is the heart of YarWeb. It does all the backend and core functions including- concatenating strings, removing duplicates, formatting the subset into a YARA rule, testing the YARA rule using yara-python, storing user information, hashing the credentials, updating the YARA rule, conducting a succinct login process, and use third-party vendor support for malware scanning.

These Python packages are to be installed on the host device:

![image](https://github.com/Laalas333/YarWeb/assets/141653171/fa3dd37e-bb49-4c50-830f-755996e5b65b)
<center>Fig 1.1</center>

# File setup:
6 folders are to be available in the current working directory for YarWeb to function. These folders will be explained individually below:

![image](https://github.com/Laalas333/YarWeb/assets/141653171/483a7d4b-1c3e-4785-b292-77f311168f56)
<center>Fig 1.2</center>

Instance is a folder created by the script in association with the SQLAlchemy package. The purpose of this directory is to store a users.db file. This database file contains all the login information about the users who have registered on YarWeb. It is to be noted, that all the user-sensitive information such as passwords are encrypted/hashed before being stored in the database using the Python package bcyrpt.
test_malwares is a folder that contains all the malware signature folders. Subsequently, these signature folders store malware samples of their own. These files are used to create the .csv files i.e. the database for rule creation.

temp is a folder that stores data only temporarily. This is primarily used whenever the user/admin has to perform an upload function. When the data is uploaded, it is stored in the temp folder for a short amount of time. When the task is completed, the file is automatically deleted from the folder.

templates this folder holds all the necessary HTML files for the front end of YarWeb.

yara_files is a folder that stores all the YARA rules produced from the interaction. The Python script ensures that if multiple users were to work on the same malware signature, only one YARA rule is stored in the directory. This is done to reduce duplicates and redundant YARA rules. Moreover, this directory is called upon at the time of rule updation. Strings from the user are concatenated to the chosen rule present in the directory, which successfully updates it.

Malware_for_testing is a folder that contains signature folders very similar to test_malwares folder. However, the malware samples included here are purely for testing purposes and are not used for the creation of the database. In YarWeb when the user is led to the testing stage, the user can use samples from these signature folders. However, it is not limited to only these test samples.

Make sure that the .csv databases are not stored together in a folder of their own. If done so, changes would have to be made to the final.py script. The Python script should also be in the current working directory but not in a separate folder within the directory. An ideal setup would look like this:

![image](https://github.com/Laalas333/YarWeb/assets/141653171/12504e17-d006-4270-8308-2fbfb3755627)
<center>Fig 1.3</center>

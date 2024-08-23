import mysql.connector
dataBase=mysql.connector.connect(
    host='localhost',
    user = 'root',
    passwd= '12345',

)

# preprae cursor object 

cusrorObject= dataBase.cursor()


cusrorObject.execute("CREATE DATABASE CIPHER")
print("All Done!")
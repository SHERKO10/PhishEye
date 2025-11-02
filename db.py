import psycopg2
import pandas as pd

# Connexion à la base PostgreSQL
conn = psycopg2.connect(
    dbname="phisheye_db",
    user="sherko",
    password="sherko",
    host="localhost",
    port="5432"
)


# Lire les données d'une table avec pandas
df = pd.read_sql("SELECT * FROM bases_donnees_listeblanche  LIMIT 10;", conn)

print(df)

conn.close()

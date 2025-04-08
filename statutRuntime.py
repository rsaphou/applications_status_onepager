import requests
import json
import logging
from datetime import datetime
import csv
import os
from dotenv import load_dotenv

CSV_FILE = 'output.csv'

ORG_ID=os.getenv("ORG_ID")

ENVIRONMENTS = [("DEV", os.getenv("DEV")),
                ("TEST", os.getenv("TEST")),
                ("TEST2", os.getenv("TEST2")),
                ("TEST3", os.getenv("TEST3")),
                ("PREPROD", os.getenv("PREPROD"))]

#Client ID/Secret set in environment variable, to use as connectedApp
CLIENT_ID=os.getenv("CLIENT_ID")
CLIENT_SECRET=os.getenv("CLIENT_SECRET")

#URL 
URL_TOKEN="https://eu1.anypoint.mulesoft.com/accounts/api/v2/oauth2/token"
URL_VIZ_NODES=f"https://eu1.anypoint.mulesoft.com/visualizer/api/v4/organizations/{ORG_ID}/applications-network/nodes/apis"
URL_VIZ=f"https://eu1.anypoint.mulesoft.com/visualizer/api/v4/organizations/{ORG_ID}/applications-network"
URL_ALL_APPLICATIONS = "https://eu1.anypoint.mulesoft.com/cloudhub/api/v2/applications"
URL_APIM=f"https://eu1.anypoint.mulesoft.com/apimanager/api/v1/organizations/{ORG_ID}/environments/"
ELK_APIKEY=os.getenv("ELK_APIKEY")
URL_ELK=os.getenv("URL_ELK")

HEADERS_ELK = {
        "Authorization": ELK_APIKEY
    }

global token
global headers_viz 
global headers
headers_token = {
    "Content-Type": "application/x-www-form-urlencoded"
}
body_token = {
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "grant_type": "client_credentials"
}


def getTokenFromAnypoint() :
    print("Load token")
    access_token=""
    response_token = requests.post(URL_TOKEN, data=body_token, headers=headers_token)
    response_token.raise_for_status() 
    dataToken = response_token.json()
    access_token = dataToken.get("access_token") #dataApimNode.get("id")
    #TOKEN = access_token
    print(f"access_token : {access_token}")
    return access_token 

def buildHeaders(token, env_id): 
    #heades = {""}
   
    headers_viz = {
    "X-ANYPNT-ENV-ID": env_id,
    "X-ANYPNT-ORG-ID" : ORG_ID,
    "Authorization": "Bearer "+ token
    }   
    
    headers_runtime = {
    "X-ANYPNT-ENV-ID": env_id,
    "Authorization": "Bearer "+ token
    }
    return headers_runtime, headers_viz

def find_first_id(obj):
    if isinstance(obj, dict):
        if "id" in obj:
            return obj["id"]  # Retourne immédiatement le premier ID trouvé
        for value in obj.values():
            result = find_first_id(value)
            if result is not None:
                return result
    elif isinstance(obj, list):
        for item in obj:
            result = find_first_id(item)
            if result is not None:
                return result
    return None  # Si aucun ID trouvé

def getAPIMIDFromViz(entityViz) :
    #print(f"Entity Viz : {entityViz}")
    apimId = None 
    if entityViz != None and entityViz != '' : 
        body_node_viz = {"entityIds":[entityViz]}
        response_apiNode = requests.post(URL_VIZ_NODES, json=body_node_viz, headers=headers_viz)
        response_apiNode.raise_for_status() 
        dataApimNode = response_apiNode.json()
        apimId = find_first_id(dataApimNode) #dataApimNode.get("id")
    return apimId 


def getIdByClusterId(response, cluster_id):
    #print(f"Cluster recherché : {cluster_id}")
    for node in response.get("nodes", []):
        #print(f"Noeud : {node}")
        if node.get("clusterId") == cluster_id:
            return node.get("id")
    return None

def getStatusAPIM(apimID, env_id) :
    #print(f"apimID : {apimID}")
    status = "Inactive" 
    if apimID != None and apimID != '' : 
        try:
            response_StatusAPIM = requests.get(URL_APIM+env_id+"/apis/"+apimID, headers=headers_runtime)
            response_StatusAPIM.raise_for_status() 
            dataAPIM = response_StatusAPIM.json()
            status = dataAPIM.get("status")
        except requests.exceptions.HTTPError as e:
            if response_StatusAPIM.status_code == 404:
                print(f"404 Not Found: {URL_APIM+env_id+"/apis/"+apimID}")
            else:
                print(f"HTTP error occurred for {URL_APIM+env_id+"/apis/"+apimID}: {e}")
        except Exception as e:
            print(f"Other error occurred for {URL_APIM+env_id+"/apis/"+apimID}: {e}")
    return status 

def getSecurityPolicy(apimID,env_id) :
    policy = "Aucune" 
    if apimID != None and apimID != '' : 

        try:
            response_policy = requests.get(URL_APIM+env_id+"/apis/"+apimID+"/policies", headers=headers_runtime)
            response_policy.raise_for_status() 
            policyAPIM = response_policy.json()
        except requests.exceptions.HTTPError as e:
            if response_policy.status_code == 404:
                print(f"404 Not Found: {URL_APIM+env_id+"/apis/"+apimID}")
                return policy 
            else:
                print(f"HTTP error occurred for {URL_APIM+env_id+"/apis/"+apimID}: {e}")
                return policy 
        except Exception as e:
            print(f"Other error occurred for {URL_APIM+env_id+"/apis/"+apimID}: {e}")
            return policy 

        try:
            asset_id = policyAPIM["policies"][0]["template"]["assetId"]
            if policyAPIM:
                #print(f"template.assetId : {asset_id}")
                policy = asset_id
            else:
                print("template.assetId est vide ou null.")
        except (KeyError, IndexError):
            print("template.assetId est introuvable dans le JSON.")
    return policy 

def callElk(URL_ELK, headers_elk, application_status):
    #response_elk= requests.post(URL_ELK, json=application_status, headers=headers_elk)
    URL_ELK_APP = URL_ELK + "/" + application_status["Application"]
    response_elk= requests.put(URL_ELK_APP, json=application_status, headers=headers_elk)

    response_elk.raise_for_status() 
    dataELK = response_elk.json()
    print(f"retour elk : {dataELK}")

def listApplications(URL_VIZ, URL_ALL_APPLICATIONS, env_id, headers_viz, headers_runtime):
    response_listApp = requests.get(URL_ALL_APPLICATIONS, headers=headers_runtime)
    response_listApp.raise_for_status()  # Gérer les erreurs HTTP

    body_viz = {"selectedEnvIdsByOrgId":{ORG_ID:[env_id]}}
    
    response_viz = requests.post(URL_VIZ, json=body_viz,headers=headers_viz)
    response_viz.raise_for_status()
   
    # Charger les données JSON
    data_listApp = response_listApp.json()
    data_viz=response_viz.json()
    #print(f"Resultat viz {data_viz}")
    #print(f"Liste des application {data_listApp}")
    return data_listApp,data_viz

# Boucle pour chaque environnement
for c_env_name, c_env_id in ENVIRONMENTS:
    load_dotenv()
    ENV = c_env_name
    ENV_ID = c_env_id
    print(f"\nStaut env  : {c_env_name} and id {c_env_id} ")
    try:
        # Récupèration du token Anypoint
        token = getTokenFromAnypoint()

        #Construire les headers de l'API Visualizer
        headers_runtime, headers_viz = buildHeaders(token,ENV_ID)

        # Récupération de la liste des applications de l'Organisation ORG_ID
        data, data_viz = listApplications(URL_VIZ, URL_ALL_APPLICATIONS, ENV_ID, headers_viz, headers_runtime)

        # Extraction des informations nécessaires
        extracted_data = []
        for item in data:
            application_status = dict()
            #application_status["VersionID"] = item.get("versionId")
            application_status["Application"] = item.get("domain")
            application_status["Dernier deploiement"] = datetime.fromtimestamp(item.get("lastUpdateTime", 0) / 1000).strftime('%d-%m-%Y %H:%M:%S')
            application_status["Statut"] = item.get("status")
            application_status["Version deployee"] = item.get("properties", {}).get("application.version")
            application_status["Nombre de worker"] = item.get("workers", {}).get("amount")
            application_status["Taille du worker"] = item.get("workers", {}).get("type", {}).get("weight")
            application_status["Version Runtime"] = item.get("muleVersion", {}).get("version")

            #Récupération de l'identifiant de l'application dans l'object Visualizer chargé.
            vizID = getIdByClusterId(data_viz, item.get("versionId"))
            application_status["Entity Vizualizer ID"] = vizID
            apimIdLoaded = getAPIMIDFromViz(vizID)
            if(apimIdLoaded is None):
                application_status["API ID"] = "vide" #item.get("properties", {}).get("api.id")
            else :
                application_status["API ID"] = apimIdLoaded #item.get("properties", {}).get("api.id")
            application_status["APIM Statut"] = getStatusAPIM(apimIdLoaded,ENV_ID)  #getStatusAPIM(item.get("properties", {}).get("api.id"))
            application_status["Securite API"] =  getSecurityPolicy(apimIdLoaded,ENV_ID) #getSecurityPolicy(item.get("properties", {}).get("api.id"))
            application_status["Environnement"] = ENV

            extracted_data.append(application_status)

            #Envoie du Staut des applications à ELK pour le Dashboard
            callElk(URL_ELK, HEADERS_ELK, application_status)

        # Affichage formaté
        print(json.dumps(extracted_data, indent=4, ensure_ascii=False))

        with open(CSV_FILE, mode='w', newline='') as file:
        # Create a CSV DictWriter object
            writer = csv.DictWriter(file, fieldnames=extracted_data[0].keys(),delimiter=";")
        # Write the header (fieldnames) to the CSV file
            writer.writeheader()
        # Write the rows of data to the CSV
            writer.writerows(extracted_data)
        print(f"CSV file '{CSV_FILE}' has been created successfully!")  

    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la requête HTTP : {e}")
    except json.JSONDecodeError:
        print("Erreur lors du décodage du JSON reçu.")

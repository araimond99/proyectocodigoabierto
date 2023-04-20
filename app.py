from flask import Flask, render_template, request
import requests
import urllib3

# Deshabilitar las advertencias de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


app = Flask(__name__)
app.debug = True
WAZUH_API_URL = "https://10.34.1.184:55000"
WAZUH_API_USERNAME = "wazuh"
WAZUH_API_PASSWORD = "wazuh"  # Reemplaza esto con la contraseña real del usuario 'admin'

def get_auth_token():
    url = f"{WAZUH_API_URL}/security/user/authenticate"
    response = requests.get(url, auth=(WAZUH_API_USERNAME, WAZUH_API_PASSWORD), verify=False)
    token = response.json()["data"]["token"]
    return token


@app.route("/")
def index():
    token = get_auth_token()
    headers = {"Authorization": f"Bearer {token}"}
    # Aquí puedes agregar código adicional para obtener información de la API y pasarla a la plantilla de renderizado
    return render_template("index.html")
def get_vulnerabilities_by_severity(token, severity):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{WAZUH_API_URL}/vulnerability"

    connected_agents = get_connected_agents(token)
    vulnerabilities = []

    for agent in connected_agents:
        agent_id = agent["id"]
        agent_url = f"{url}/{agent_id}"
        params = {"severity": severity}
        response = requests.get(agent_url, headers=headers, params=params, verify=False)
        
        # Agrega el ID del agente a cada vulnerabilidad
        agent_vulnerabilities = response.json()["data"]["affected_items"]
        for vulnerability in agent_vulnerabilities:
            vulnerability["agent_id"] = agent_id
        
        vulnerabilities.extend(agent_vulnerabilities)

    return vulnerabilities


  
def get_connected_agents(token):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{WAZUH_API_URL}/agents"
    params = {"status": "Active"}
    response = requests.get(url, headers=headers, params=params, verify=False)
    agents = response.json()["data"]["affected_items"]
    print("Agentes:", agents)  # Agregar mensaje de depuración
    return agents


@app.route("/connected_agents")
def connected_agents():
    token = get_auth_token()
    agents = get_connected_agents(token)
    return render_template("connected_agents.html", agents=agents)


@app.route("/vulnerabilities")
def vulnerabilities():
    token = get_auth_token()
    severity = request.args.get("severity", "all")
    vulnerabilities = get_vulnerabilities_by_severity(token, severity)
    return render_template("vulnerabilities.html", vulnerabilities=vulnerabilities)
#funciones para el 2
def get_vulnerabilities_by_keyword(token, keyword):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = f"{WAZUH_API_URL}/agents"
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code != 200:
        return []

    agents = response.json()['data']['affected_items']
    filtered_vulnerabilities = []

    for agent in agents:
        agent_id = agent['id']
        url = f"{WAZUH_API_URL}/vulnerability/{agent_id}"
        response = requests.get(url, headers=headers, verify=False)

        if response.status_code == 200:
            vulnerabilities = response.json()['data']['affected_items']
            for vuln in vulnerabilities:
                if keyword.lower() in vuln['name'].lower():
                    filtered_vulnerabilities.append(vuln)

    return filtered_vulnerabilities

@app.route("/search_vulnerabilities", methods=["GET", "POST"])
def search_vulnerabilities():
    token = get_auth_token()
    if request.method == "POST":
        keyword = request.form["keyword"]
        vulnerabilities = get_vulnerabilities_by_keyword(token, keyword)
        return render_template("search_vulnerabilities.html", vulnerabilities=vulnerabilities)
    return render_template("search_vulnerabilities.html", vulnerabilities=None)

#Punto 3
from flask import Flask, render_template, request, jsonify
import json





def upgrade_agent(agent: str, token: str):
    url = WAZUH_API_URL

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.put(url + '/agents/upgrade', headers=headers, params={'agents_list': agent}, verify=False)

    if response.status_code == 200:
        return f"La actualización del agente {agent} se realizó con éxito."
    elif response.status_code == 401:
        return f"Error al actualizar el agente {agent}: Token de autorización no válido."
    else:
        return f"Error al actualizar el agente {agent}: {response.text}"


def restart_agent(agent: str, token: str):
    url = WAZUH_API_URL

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.put(url + '/agents/restart', headers=headers, params={'agents_list': agent}, verify=False)

    if response.status_code == 200:
        return f"El agente {agent} se reinició con éxito."
    elif response.status_code == 401:
        return f"Error al reiniciar el agente {agent}: Token de autorización no válido."
    else:
        return f"Error al reiniciar el agente {agent}: {response.text}"

def delete_agent(agent: str, token: str):
    url = WAZUH_API_URL

    headers = {"Authorization": f"Bearer {token}"}
    params = {'pretty': True, 'older_than': '0s', 'agents_list': agent, 'status': 'all'}
    response = requests.delete(url + '/agents', headers=headers, params=params, verify=False)

    if response.status_code == 200:
        return f"El agente {agent} se eliminó con éxito."
    elif response.status_code == 401:
        return f"Error al eliminar el agente {agent}: Token de autorización no válido."
    else:
        return f"Error al eliminar el agente {agent}: {response.text}"




@app.route("/agent_actions", methods=["GET", "POST"])
def agent_actions():
    token = get_auth_token()
    action = None
    response = None

    if request.method == "POST":
        data = request.get_json()
        agent = data["agent_id"]
        action = data["action"]

        if action == "upgrade":
            response = upgrade_agent(agent, token)
        elif action == "restart":
            response = restart_agent(agent, token)
        elif action == "delete":
            response = delete_agent(agent, token)

        return jsonify({"message": response})

    return render_template("agent_actions.html")

#funciones para el punto 4
def get_agents_with_vulnerability(token, cve):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = f"{WAZUH_API_URL}/vulnerability"
    response = requests.get(url, headers=headers, params={"cve": cve}, verify=False)

    if response.status_code != 200:
        return []

    agents = response.json()['data']['affected_items']
    return agents




@app.route("/common_vulnerability", methods=["GET", "POST"])
def common_vulnerability():
    token = get_auth_token()
    if request.method == "POST":
        cve = request.form["cve"]
        agents = get_agents_with_vulnerability(token, cve)
        return render_template("common_vulnerability.html", agents=agents, cve=cve)
    return render_template("common_vulnerability.html", agents=None, cve=None)

#funciones para el punto 5
def get_top_vulnerabilities(token, limit=10):
    headers = {
        'Authorization': f'Bearer {token}'
    }

    # Obtén la lista de todos los agentes
    url_agents = f"{WAZUH_API_URL}/agents"
    response_agents = requests.get(url_agents, headers=headers, verify=False)
    agents = response_agents.json()['data']['affected_items']

    # Almacena las ocurrencias de las vulnerabilidades en un diccionario
    vulnerability_count = {}

    for agent in agents:
        agent_id = agent['id']
        url_vulnerabilities = f"{WAZUH_API_URL}/vulnerability/{agent_id}"
        response_vulnerabilities = requests.get(url_vulnerabilities, headers=headers, verify=False)
        
        # Verifica si la clave 'data' está presente en la respuesta
        if response_vulnerabilities.status_code == 200 and 'data' in response_vulnerabilities.json():
            vulnerabilities = response_vulnerabilities.json()['data']['affected_items']
        else:
            vulnerabilities = []

        for vulnerability in vulnerabilities:
            name = vulnerability['name']
            if name in vulnerability_count:
                vulnerability_count[name] += 1
            else:
                vulnerability_count[name] = 1

    # Ordena las vulnerabilidades por ocurrencias y devuelve las primeras 10
    top_vulnerabilities = sorted(vulnerability_count.items(), key=lambda x: x[1], reverse=True)[:limit]
    return top_vulnerabilities




@app.route("/top_vulnerabilities")
def top_vulnerabilities():
    token = get_auth_token()
    vulnerabilities = get_top_vulnerabilities(token)
    return render_template("top_vulnerabilities.html", vulnerabilities=vulnerabilities)
#codigo para el 6
def get_top_agents(token):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    agents_url = f"{WAZUH_API_URL}/agents"
    agents_response = requests.get(agents_url, headers=headers, verify=False)

    if agents_response.status_code != 200:
        return []

    agents = agents_response.json()['data']['affected_items']
    agent_vulnerability_count = {}
    for agent in agents:
        agent_id = agent['id']
        vulnerabilities_url = f"{WAZUH_API_URL}/vulnerability/{agent_id}"
        vulnerabilities_response = requests.get(vulnerabilities_url, headers=headers, verify=False)
        
        if vulnerabilities_response.status_code == 200:
            vulnerabilities = vulnerabilities_response.json()['data']['affected_items']
            agent_vulnerability_count[agent_id] = len(vulnerabilities)

    top_agents = sorted(agent_vulnerability_count.items(), key=lambda x: x[1], reverse=True)[:10]
    return top_agents


@app.route("/top_agents")
def top_agents():
    token = get_auth_token()
    top_agents = get_top_agents(token)
    return render_template("top_agents.html", top_agents=top_agents)
#codigo 7
from flask import jsonify
def get_server_status(token):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    endpoints = [
        ("/manager/configuration", "config"),
        ("/manager/logs", "logs"),
        ("/manager/logs/summary", "logs_summary"),
        ("/groups", "groups"),
        ("/tasks/status", "tasks_status"),
    ]
    
    status = {}
    for endpoint, key in endpoints:
        url = f"{WAZUH_API_URL}{endpoint}"
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            status[key] = response.json()
        else:
            status[key] = {'error': f"Error al obtener datos del endpoint {endpoint}"}
    
    return status

@app.route('/server_status', methods=['GET', 'POST'])
def server_status():
    if request.method == 'GET':
        return render_template('server_status.html')
    
    token = get_auth_token()
    status = get_server_status(token)
    return render_template('server_status.html', status=status)




#Puntos Extra
from pprint import pprint

def get_hardware_info(token, agent_id):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = f"{WAZUH_API_URL}/syscollector/{agent_id}/hardware"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        data = response.json()
        pprint(data)  # Agrega esta línea para mostrar los datos de forma legible
        return data
    else:
        return []

def get_hotfixes_info(token, agent_id):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = f"{WAZUH_API_URL}/syscollector/{agent_id}/hotfixes"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return []
def get_netaddr_info(token, agent_id):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = f"{WAZUH_API_URL}/syscollector/{agent_id}/netaddr"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return []

def get_netiface_info(token, agent_id):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = f"{WAZUH_API_URL}/syscollector/{agent_id}/netiface"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return []

def get_netproto_info(token, agent_id):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = f"{WAZUH_API_URL}/syscollector/{agent_id}/netproto"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return []

def get_os_info(token, agent_id):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = f"{WAZUH_API_URL}/syscollector/{agent_id}/os"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return []

def get_packages_info(token, agent_id):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = f"{WAZUH_API_URL}/syscollector/{agent_id}/packages"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return []

def get_ports_info(token, agent_id):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = f"{WAZUH_API_URL}/syscollector/{agent_id}/ports"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return []

def get_processes_info(token, agent_id):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    url = f"{WAZUH_API_URL}/syscollector/{agent_id}/processes"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return []

@app.route("/agent_inventory", methods=["GET", "POST"])
def agent_inventory():
    token = get_auth_token()
    message = None
    agent_id = None
    agent_info = {}
    
    if request.method == "POST":
        agent_id = request.form["agent_id"]
        if agent_id:
            agent_info['hardware'] = get_hardware_info(token, agent_id)
            agent_info['hotfixes'] = get_hotfixes_info(token, agent_id)
            agent_info['netaddr'] = get_netaddr_info(token, agent_id)
            agent_info['netiface'] = get_netiface_info(token, agent_id)
            agent_info['netproto'] = get_netproto_info(token, agent_id)
            agent_info['os'] = get_os_info(token, agent_id)
            agent_info['packages'] = get_packages_info(token, agent_id)
            agent_info['ports'] = get_ports_info(token, agent_id)
            agent_info['processes'] = get_processes_info(token, agent_id)
        else:
            message = "Debe ingresar un ID de agente válido"
    
    return render_template("agent_inventory.html", message=message, agent_info=agent_info, agent_id=agent_id)


if __name__ == "__main__":
    app.run(debug=True)


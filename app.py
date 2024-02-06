from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_mysqldb import MySQL
from datetime import datetime
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
import bcrypt
import requests

app = Flask(__name__)
app.secret_key = 'Angel'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'Asistencia_Estudiantes'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin):
    pass


@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor()
    result = cursor.execute('SELECT * FROM usuarios WHERE id = %s', (user_id,))
    user_data = cursor.fetchone()
    cursor.close()

    if user_data:
        user = User()
        user.id = user_data['id']
        return user
    return None


# Ruta para Admin
@app.route('/Pagina_Admin')
@login_required
def Pagina_Admin():
    return render_template('P_Admin.html')


# Ruta para Profesor
@app.route('/Pagina_Profesor')
@login_required
def Pagina_Profesor():
    return render_template('P_Profesor.html')


@app.route('/obtener_estudiantes_api')
def obtener_estudiantes_api():
    cedula = "0958476533"
    campus = "GYE"


    estudiantes_api_url = f"http://173.212.212.214:5000/estudiante?cedula={cedula}&campus={campus}"
    response_estudiantes = requests.get(estudiantes_api_url)

    if response_estudiantes.status_code == 200:
        datos_estudiantes = response_estudiantes.json()
        return render_template('asistencias/Mostar_Asistencia_Admin.html', datos_estudiantes=datos_estudiantes)
    else:
        return f"Error al obtener datos de la API de estudiantes. Código de estado: {response_estudiantes.status_code}"


# Ruta para Mostar Asistencia Profesor
@app.route('/Pagina1')
@login_required
def AsistenciaProfesor():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM asistencia_usuarios')
    registros = cursor.fetchall()
    cursor.close()

    cedula = "0958476533"
    date_ini = "2024-01-01"
    date_end = "2024-01-31"

    asistencia_api_url = f"http://173.212.212.214:5000/asistencia?cedula={cedula}&date_ini={date_ini}&date_end={date_end}"
    response_asistencia = requests.get(asistencia_api_url)

    if response_asistencia.status_code == 200:
        datos_asistencia = response_asistencia.json()

        return render_template('asistencias/Mostar_Asistencia_Profesor.html', datos_asistencia=datos_asistencia,
                               registros=registros)
    else:
        return f"Error al obtener datos de la API de asistencia. Código de estado: {response_asistencia.status_code}"


# Ruta para Mostar Asistencia Admin
@app.route('/Pagina2')
@login_required
def AsistenciaAdmin():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM asistencia_usuarios')
    registros = cursor.fetchall()
    cursor.close()

    cedula = "0958476533"
    date_ini = "2024-01-01"
    date_end = "2024-01-31"

    asistencia_api_url = f"http://173.212.212.214:5000/asistencia?cedula={cedula}&date_ini={date_ini}&date_end={date_end}"
    response_asistencia = requests.get(asistencia_api_url)

    if response_asistencia.status_code == 200:
        datos_asistencia = response_asistencia.json()

        return render_template('asistencias/Mostar_Asistencia_Admin.html', datos_asistencia=datos_asistencia,
                               registros=registros)
    else:
        return f"Error al obtener datos de la API de asistencia. Código de estado: {response_asistencia.status_code}"


@app.route('/Pagina3')
@login_required
def Pagina3():
    return render_template('pagina3.html')


@app.route('/editar_datos', methods=['GET', 'POST'])
def editar_datos():
    if request.method == 'POST':
        nuevos_datos = {
            "campo1": request.form['campo1'],
            "campo2": request.form['campo2']
        }

        cedula = "095847653"
        date_ini = "2024-01-01"
        date_end = "2024-01-30"

        url = f"http://173.212.212.214:5000/asistencia/actualizar"
        params = {"cedula": cedula, "date_ini": date_ini, "date_end": date_end}

        response = requests.put(url, params=params, json=nuevos_datos)

        if response.status_code == 200:
            return redirect(url_for('mostrar_datos'))
        else:
            return f"Error al actualizar datos. Código de estado: {response.status_code}"

    return render_template('asistencias/editar_asistencia.html')

@app.route('/eliminar_datos')
def eliminar_datos():
    cedula = "0958476533"
    date_ini = "2024-01-01"
    date_end = "2024-01-30"

    url = f"http://173.212.212.214:5000/asistencia/eliminar"
    params = {"cedula": cedula, "date_ini": date_ini, "date_end": date_end}

    response = requests.delete(url, params=params)

    if response.status_code == 200:
        return redirect(url_for('mostrar_datos'))
    else:
        return f"Error al eliminar datos. Código de estado: {response.status_code}"

# Ruta para Editar un Asistencia
@app.route('/editar_asistencia/<int:usuario_id>', methods=['GET', 'POST'])
@login_required
def editar_asistencia(usuario_id):
    pagina_origen = request.args.get('pagina_origen')

    if request.method == 'POST':
        pagina_origen = request.form.get('pagina_origen')
        nueva_asistencia = request.form['asistencia']

        api_url = f"http://173.212.212.214:5000/asistencia/{usuario_id}"
        data = {"asistencia": nueva_asistencia}
        response = requests.put(api_url, json=data)

        if response.status_code == 200:
            return redirect(url_for('AsistenciaProfesor' if pagina_origen == 'pagina1' else 'AsistenciaAdmin'))
        else:
            return f"Error al actualizar la asistencia. Código de estado: {response.status_code}"

    api_url = f"http://173.212.212.214:5000/asistencia/{usuario_id}"
    response = requests.get(api_url)

    if response.status_code == 200:
        asistencia = response.json()
        return render_template('asistencias/editar_asistencia.html', asistencia=asistencia, pagina_origen=pagina_origen)
    else:
        return f"Error al obtener detalles de la asistencia. Código de estado: {response.status_code}"



# Ruta para Eliminar una Asistencia
@app.route('/eliminar_asistencia/<int:usuario_id>')
@login_required
def eliminar_asistencia(usuario_id):
    api_url = f"http://173.212.212.214:5000/asistencia/{usuario_id}"
    response = requests.delete(api_url)

    if response.status_code == 200:
        pagina_origen = request.args.get('pagina_origen')
        return redirect(url_for('AsistenciaProfesor' if pagina_origen == 'pagina1' else 'AsistenciaAdmin'))
    else:
        return f"Error al eliminar la asistencia. Código de estado: {response.status_code}"


# Ruta para mostrar Usuario
@app.route('/usuarios')
@login_required
def mostrar_usuarios():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM usuarios')
    usuarios = cursor.fetchall()
    cursor.close()
    return render_template('usuarios/usuarios.html', usuarios=usuarios)


# Ruta para Editar un Usuario
@app.route('/usuarios/editar_usuario/<int:usuario_id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(usuario_id):
    if request.method == 'POST':
        nuevo_nombre = request.form['nombre']
        nuevo_apellido = request.form['apellido']
        nueva_cedula = request.form['cedula']
        nuevo_email = request.form['email']
        nuevo_id_rol = request.form['id_rol']

        cursor = mysql.connection.cursor()
        cursor.execute(
            'UPDATE usuarios SET nombre = %s, apellido = %s, cedula = %s, email = %s, id_rol = %s WHERE id = %s',
            (nuevo_nombre, nuevo_apellido, nueva_cedula, nuevo_email, nuevo_id_rol, usuario_id))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('mostrar_usuarios'))

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM usuarios WHERE id = %s', (usuario_id,))
    usuario = cursor.fetchone()
    cursor.close()

    return render_template('usuarios/editar_usuario.html', usuario=usuario)

    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM usuarios WHERE id = %s', (usuario_id,))
    usuario = cursor.fetchone()
    cursor.close()

    return render_template('usuarios/editar_usuario.html', usuario=usuario)


# Ruta para Eliminar un Usuario
@app.route('/usuarios/eliminar_usuario/<int:usuario_id>')
@login_required
def eliminar_usuario(usuario_id):
    cursor = mysql.connection.cursor()
    cursor.execute('DELETE FROM usuarios WHERE id = %s', (usuario_id,))
    mysql.connection.commit()
    cursor.close()

    return redirect(url_for('mostrar_usuarios'))


# Ruta para el registro de usuario
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        cedula = request.form['cedula']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        cursor = mysql.connection.cursor()
        emailerror = cursor.execute('SELECT * FROM usuarios WHERE email = %s', (email,))
        cedulaerror = cursor.execute('SELECT * FROM usuarios WHERE cedula = %s', (cedula,))

        if emailerror > 0:
            error = 'El email ya están en uso. Por favor, elige otro.'
            return render_template('login/registro.html', error=error)
        elif cedulaerror > 0:
            error = 'La cedula ya están en uso. Por favor, elige otro.'
            return render_template('login/registro.html', error=error)

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        fecha_creacion = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        id_rol_predeterminado = 2

        cursor.execute(
            'INSERT INTO usuarios (nombre, apellido, cedula, email, password, fecha_creacion, id_rol) VALUES (%s, %s, %s, %s, %s, %s, %s)',
            (nombre, apellido, cedula, email, hashed_password, fecha_creacion, id_rol_predeterminado))
        mysql.connection.commit()
        cursor.close()

        cursor = mysql.connection.cursor()
        result = cursor.execute('SELECT * FROM usuarios WHERE cedula = %s', (cedula,))
        user_data = cursor.fetchone()
        cursor.close()

        if result > 0:
            user = User()
            user.id = user_data['id']
            login_user(user)

        return redirect(url_for('login'))

    return render_template('login/registro.html')


# Ruta para el login
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        cedula = request.form['cedula']
        password_candidate = request.form['password'].encode('utf-8')

        cursor = mysql.connection.cursor()
        result = cursor.execute('SELECT * FROM usuarios WHERE cedula = %s', (cedula,))

        if result > 0:
            data = cursor.fetchone()
            password = data['password'].encode('utf-8')

            if bcrypt.checkpw(password_candidate, password):
                user = User()
                user.id = data['id']
                user.id_rol = data['id_rol']
                user.nombre = data['nombre']
                user.cedula = data['cedula']
                fecha_actual = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute('UPDATE usuarios SET fecha_ingreso = %s WHERE cedula = %s',
                               (fecha_actual, cedula))
                mysql.connection.commit()

                cursor.execute(
                    'INSERT INTO registros_ingreso (id_usuario, fecha_ingreso, nombre, cedula) VALUES (%s, %s,%s, %s)',
                    (data['id'], fecha_actual, data['nombre'], data['cedula']))
                mysql.connection.commit()
                login_user(user)

                if user.id_rol == 1:
                    return redirect(url_for('mostrar_usuarios'))
                elif user.id_rol == 2:
                    return redirect(url_for('AsistenciaProfesor'))

            else:
                error = 'Contraseña incorrecta'
                return render_template('login/login.html', error=error)
        else:
            error = 'Usuario no encontrado'
            return render_template('login/login.html', error=error)

    return render_template('login/login.html')


# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.secret_key = 'Angel'
    app.run(debug=True)

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from datetime import timedelta, datetime
from bson.objectid import ObjectId
from config import Config


from itsdangerous import URLSafeTimedSerializer
from flask import session

app = Flask(__name__)
app.config.from_object(Config)
print("MONGO_URI:", app.config.get('MONGO_URI'))


s = URLSafeTimedSerializer(app.config['SECRET_KEY'])



# VALIDACIÓN
if not app.config.get("MONGO_URI"):
    raise RuntimeError("ERROR: No se encontró la variable MONGO_URI")

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.permanent_session_lifetime = timedelta(minutes=10)  # Sesión expira a los 10 min

class User(UserMixin):
    def __init__(self, user_doc):
        self.id = str(user_doc['_id'])
        self.username = user_doc['username']
        self.permissions = user_doc.get('permissions', [])

@login_manager.user_loader
def load_user(user_id):
    user_doc = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_doc) if user_doc else None

@app.before_request
def session_timeout():
    session.permanent = True
    session.modified = True

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form.get('confirm_password')

        if password != confirm:
            flash("Las contraseñas no coinciden.")
            return redirect(url_for('register'))

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        if mongo.db.users.find_one({'username': username}):
            flash('El usuario ya existe.')
            return redirect(url_for('register'))

        default_permissions = ['admin'] if username == 'admin' else []
        mongo.db.users.insert_one({
            'username': username,
            'password': password_hash,
            'permissions': default_permissions
        })

        flash('Registro exitoso. Ahora puedes iniciar sesión.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = mongo.db.users.find_one({'username': request.form['username']})
        if user and bcrypt.check_password_hash(user['password'], request.form['password']):
            login_user(User(user))
            if 'admin' in user.get('permissions', []):
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
        flash('Credenciales incorrectas')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username, permissions=current_user.permissions)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada')
    return redirect(url_for('login'))

@app.route('/panel/<panel_name>')
@login_required
def panel(panel_name):
    if panel_name not in current_user.permissions:
        return render_template('unauthorized.html')
    return f"Bienvenido al panel: {panel_name}"

@app.route('/admin/set_permissions', methods=['POST'])
@login_required
def set_permissions():
    if current_user.username != 'admin':
        return redirect(url_for('unauthorized'))
    username = request.form['username']
    permissions = request.form.getlist('permissions')
    mongo.db.users.update_one({'username': username}, {'$set': {'permissions': permissions}})
    flash('Permisos actualizados')
    return redirect(url_for('dashboard'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if 'admin' not in current_user.permissions:
        flash("Acceso denegado.")
        return redirect(url_for('dashboard'))

    users_collection = mongo.db.users

    permisos_disponibles = [
        'Críticos', 'Custodia', 'Hierro_Ductil', 'Cajas_medidores', 'Suministro_EPP', 'Dotación',
        'Abrazaderas_metálicas', 'Válvulas_mariposa', 'Tubería_ACC_PVC', 'Accesorios_PEAD',
        'Tubería_PEAD', 'Lubricantes', 'Llantería', 'Tornillería',
        'Materiales_compactación', 'General', 'Tapabocas'
    ]

    if request.method == 'POST':
        username = request.form['username']
        permissions = request.form.getlist('permissions')
        users_collection.update_one({'username': username}, {'$set': {'permissions': permissions}})
        flash(f"Permisos actualizados para {username}.")

    all_users = list(users_collection.find({}, {'username': 1, 'permissions': 1, '_id': 0}))

    return render_template('admin.html', users=all_users, permisos_disponibles=permisos_disponibles)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        user = mongo.db.users.find_one({'username': username})
        if user:
            token = s.dumps(username, salt='reset-password')
            reset_url = url_for('change_password_token', token=token, _external=True)
            flash(f'Usa este enlace para restablecer tu contraseña: {reset_url}')
        else:
            flash('Usuario no encontrado.')
    return render_template('reset_password.html')

@app.route('/change_password/<token>', methods=['GET', 'POST'])
def change_password_token(token):
    try:
        username = s.loads(token, salt='reset-password', max_age=900)  # 15 min
    except Exception as e:
        return 'Enlace expirado o inválido', 403

    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        mongo.db.users.update_one({'username': username}, {'$set': {'password': hashed_password}})
        flash('Contraseña actualizada correctamente.')
        return redirect(url_for('login'))

    return render_template('change_password.html')

if __name__ == '__main__':
    app.run()

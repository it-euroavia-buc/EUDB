"""
1. Fisierul main.py - aici se apeleaza functia create_app() din __init__.py
2. De aici vom rula aplicatie de fiecare data
3. Nimic de schimbat aici
"""

from website import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)


"""
Info despre comenzile GIT: http://guides.beanstalkapp.com/version-control/common-git-commands.html

"""

"""
Link-uri utile:

1. Documentatie Python: https://docs.python.org/3/
2. Documentatie Flask: https://flask.palletsprojects.com/en/2.2.x/
3. Documentatie SQLAlchemy: https://docs.sqlalchemy.org/en/14/
4. Video Flask: https://www.youtube.com/watch?v=dam0GPOAvVI&ab_channel=TechWithTim
5. Proiect Personal Flask (aplicatie votare):
6. Proiect Personal Flask (database): 
7. Proiect Flask Tim (cod sursa link nr 4): https://github.com/techwithtim/Flask-Web-App-Tutorial/tree/main/website
"""
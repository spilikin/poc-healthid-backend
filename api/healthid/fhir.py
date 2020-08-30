from fhirclient.models.humanname import HumanName
from fhirclient.models.patient import Patient
from fhirclient.models.fhirdate import FHIRDate
import isodate
from datetime import timedelta, date
from random import choice, uniform
from uuid import uuid4

def random_patient() -> Patient:
    given_names = open('given_names.csv', 'r').read().split('\n')
    given_names_male = []
    given_names_female = []
    for nameinfo in given_names:
        if nameinfo == "":
            break
        (name, gender) = nameinfo.split(',')
        if gender == 'w':
            given_names_female.append(name)
        else:
            given_names_male.append(name)


    family_names = open('family_names.csv', 'r').read().split('\n')

    # 25% of the times we will have two given names
    amount_given_names = choice([1, 1, 1, 2])

    patient = Patient({'id': str(uuid4())})

    gender = choice(['male', 'female'])
    if gender == 'male':
        given_names = given_names_male
    else:
        given_names = given_names_female

    patient.gender = gender

    name = HumanName()
    name.given = []
    for i in range(amount_given_names):
        name.given.append(given_names[int(uniform(0, len(given_names)-1))])
    name.family = family_names[int(uniform(0, len(family_names)-1))]
    patient.name = [name]

    age_in_days = int(uniform(16*365, 60*365))
    birthDate = date.today() - timedelta(days=age_in_days)

    patient.birthDate = FHIRDate(str(birthDate))
    return patient
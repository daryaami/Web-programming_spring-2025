from typing import List, Optional
from fastapi import FastAPI
from typing_extensions import TypedDict

from models import Profession, Warrior

app = FastAPI()

temp_bd = [
{
    "id": 1,
    "race": "director",
    "name": "Мартынов Дмитрий",
    "level": 12,
    "profession": {
        "id": 1,
        "title": "Влиятельный человек",
        "description": "Эксперт по всем вопросам"
    },
    "skills":
        [{
            "id": 1,
            "name": "Купле-продажа компрессоров",
            "description": ""

        },
        {
            "id": 2,
            "name": "Оценка имущества",
            "description": ""
        }]
},
{
    "id": 2,
    "race": "worker",
    "name": "Андрей Косякин",
    "level": 12,
    "profession": {
        "id": 1,
        "title": "Дельфист-гребец",
        "description": "Уважаемый сотрудник"
    },
    "skills": []
},
]

@app.get("/")
def hello():
    return "Hello!"


@app.get("/warriors_list")
def warriors_list() -> List[Warrior]:
    return temp_bd


@app.get("/warrior/{warrior_id}")
def warriors_get(warrior_id: int) -> List[Warrior]:
    return [warrior for warrior in temp_bd if warrior.get("id") == warrior_id]


@app.post("/warrior")
def warriors_create(warrior: Warrior) -> TypedDict('Response', {"status": int, "data": Warrior}):
    warrior_to_append = warrior.model_dump()
    temp_bd.append(warrior_to_append)
    return {"status": 200, "data": warrior}


@app.delete("/warrior/delete{warrior_id}")
def warrior_delete(warrior_id: int):
    for i, warrior in enumerate(temp_bd):
        if warrior.get("id") == warrior_id:
            temp_bd.pop(i)
            break
    return {"status": 201, "message": "deleted"}


@app.put("/warrior{warrior_id}")
def warrior_update(warrior_id: int, warrior: Warrior) -> List[Warrior]:
    for war in temp_bd:
        if war.get("id") == warrior_id:
            warrior_to_append = warrior.model_dump()
            temp_bd.remove(war)
            temp_bd.append(warrior_to_append)
    return temp_bd

# CRUD для профессий
@app.get("/professions")
def professions_list() -> List[Profession]:
    return temp_professions

@app.get("/profession/{profession_id}")
def profession_get(profession_id: int) -> Optional[Profession]:
    for profession in temp_professions:
        if profession.id == profession_id:
            return profession
    return None

@app.post("/profession")
def profession_create(profession: Profession) -> dict:
    temp_professions.append(profession)
    return {"status": 200, "data": profession}


@app.delete("/profession/{profession_id}")
def profession_delete(profession_id: int):
    global temp_professions
    temp_professions = [prof for prof in temp_professions if prof.id != profession_id]
    return {"status": 201, "message": "deleted"}


@app.put("/profession/{profession_id}")
def profession_update(profession_id: int, profession: Profession) -> List[Profession]:
    for i, prof in enumerate(temp_professions):
        if prof.id == profession_id:
            temp_professions[i] = profession
            break
    return temp_professions

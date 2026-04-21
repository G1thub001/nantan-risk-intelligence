from fastapi import FastAPI
from pydantic import BaseModel
from Prediict import final_decision

app = FastAPI(title="Phishing Detection API")

class EmailRequest(BaseModel):
    content: str

@app.get("/")
def root():
    return {"message": "Phishing Detection API is running 🚀"}

@app.post("/analyze")
def analyze_email(request: EmailRequest):
    result = final_decision(request.content)
    return result
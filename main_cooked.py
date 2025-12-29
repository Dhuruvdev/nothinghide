from fastapi import FastAPI
from cookie_cooked import cookie_cooked_middleware
from cookie_cooked_api import router as protection_router

app = FastAPI(title="Cookie Cooked Protection System")

# Register Middleware
@app.middleware("http")
async def add_cookie_cooked_protection(request, call_next):
    return await cookie_cooked_middleware(request, call_next)

# Register API Routes
app.include_router(protection_router)

@app.get("/")
async def root():
    return {"message": "Cookie Cooked Protection System is Active"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)

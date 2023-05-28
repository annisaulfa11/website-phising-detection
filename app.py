#### library untuk memanggil model pickle ####
import joblib
### END ###

#### Library untuk membuat documentasi REST API ###
from fastapi import FastAPI, Request, Form
#### END ###

#### Library untuk menjalankan server local ####
import uvicorn
### END ###
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from URLfeature import *

#### Definisi Fast API ###
app=FastAPI()
templates = Jinja2Templates(directory="templates/")
app.mount("/static", StaticFiles(directory="static"), name="static")
#### END ####

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

#### Memanggil Model Pickle Yang Gunanya untuk insialisasi posisi model yang mau di ekseskusi dengan menggukan liblary joblib ####
phish_model = open('models/Phishing_Detection_Model.pkl','rb')
phish_model_ls = joblib.load(phish_model)
#### END ####

#### Halaman Root Awal ####
# app.get('/') adalah routelist yang nantinya di akses pertama kali misal localhost:8000/ #
# def read_root adalah suatu method #
# retrun {"heloo":"world"} fungsi yang nanti di balikan ke view #
# @app.get("/")
# def read_root():
#     return {"Hello":"world"}
#### END ####

### Halaman untuk predict ###
# @app.get('/predict/{feature}') adalah routes list yang nantinya di akses yang membawa pramater query feature ###
# async def predict(feauteres): membuat method yang membawa paramater features unutuk menampung hasil parameter yang di tentukan #
# decetion_result = [] suatu variable untuk menampung array kosong yang nantinya akan diisi value dari request data #
# decetion(feauteres) suatu fungsi dari modul URLfeature untuk mengektrak url feature dari url #
# y_Predict = phish_model_ls.predict(decetion_result)[0] memanggil model yang sudah di definisakn di atas untuk predict hasil dari decetion_result yang ada di dalam array #
@app.get('/')
async def index(request: Request):
    return templates.TemplateResponse('index.html', context={'request': request})

@app.post('/predict')
async def predict(request: Request, url: str = Form(...)):
    decetion_result = decetion(url)
    y_Predict = phish_model_ls.predict(decetion_result)[0]
    ### Logic Predict Dari hasil decetion_result ###
    # jika hasil array dari decetion_result yang nantinya di proses dengan y_Predict hasilnya 1 nantinya akan mengembalikan string situs ini adalah pihising dan jika hasinya bukan 1 akan menghasilkan string situs ini bukan phising #
    if y_Predict == 1:
        result = "Situs ini tidak aman"
    else:
        result = "Kami tidak menemukan tautan ini berbahaya"
    ### END ###

    ### membuat variable data yang berisi object yang nantinya akan mengebalikan response dari request yang dikirim dan hasil yang sudah di proses dari decetion_result dan y_predict dalam bentuk object ###
    data = {'url':url,'data':result}
    return templates.TemplateResponse('index.html', context={'request': request, 'result': result, 'url': url, 'predict' : y_Predict})

#### END ###


### salah satu fungsi untuk menjalankan local server yang menggunakan library uvicorn ###
if __name__ == '__main__':
    uvicorn.run(app,host="127.0.0.1",port=8000)
### END ###


# api doc http://127.0.0.1:8000/docs/

### END ###
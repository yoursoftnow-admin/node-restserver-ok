const express = require('express');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const CLIENT_ID = process.env.CLIENT_ID;
const {OAuth2Client} = require('google-auth-library');
const client = new OAuth2Client(CLIENT_ID);

const Usuario = require('../models/usuario');

const app = express();



app.post('/login', (req, res) => {

    let body = req.body;

    Usuario.findOne({ email: body.email }, (err, usuarioDB) => {

        if (err) {
            return res.status(500).json({
                ok: false,
                err
            });
        }

        if (!usuarioDB) {
            return res.status(400).json({
                ok: false,
                err: {
                    message: '(Usuario) o contraseña incorrectos'
                }
            });
        }


        if (!bcrypt.compareSync(body.password, usuarioDB.password)) {
            return res.status(400).json({
                ok: false,
                err: {
                    message: 'Usuario o (contraseña) incorrectos'
                }
            });
        }

        let token = jwt.sign({
            usuario: usuarioDB
        }, process.env.SEED, { expiresIn: process.env.CADUCIDAD_TOKEN });

        res.json({
            ok: true,
            usuario: usuarioDB,
            token
        });


    });

});

//configuraciones de google;
async function verify(token) {
    const ticket = await client.verifyIdToken({
        idToken: token,
        audience: CLIENT_ID  // Specify the CLIENT_ID of the app that accesses the backend
        // Or, if multiple clients access the backend:
        //[CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]
    });
    const payload = ticket.getPayload();
    // console.log(payload.name);
    // console.log(payload.email);
    // console.log(payload.picture);
    return {
        nombre:payload.name,
        email:payload.email,
        img:payload.picture,
        google:true
    };
  }

app.post('/google', async(req, res) => {//Validando los inicios de sesion con google sign
    let token=req.body.idtoken;//Tomamos el token que viene del front
    let googleUser=await verify(token)//Mandamos a verificar el token y nos retorna el payload con la info del user
    .catch(err=>{//Hacemos un catch en caso de error
        return res.status(403).json({//retornamos la respuesta con el error
            ok:false,
            err
        })
    })
    
    //Validar a traves del email si el usuario ya existe en la BD
    Usuario.findOne({email:googleUser.email},(err,usDB)=>{//Buscamos en la base de datos usuario que conicida con el email
        if(err){//Si nos ta error retornamos el error 500
            return res.status(500).json({
                ok:false,
                err
            })
        }


        if(usDB){//si se logra obtener el usuario es decir si este ya existe en nuestra DB
            if(!usDB.google){//Si este fue autenticado por google
                return res.status(400).json({//Si no fue autenticado por google le mandamos a que se autentique normal o podria ser un reset pass
                    ok:false,
                    err:{
                        message:'Debe usar su autenticación normal'
                    }
                })
            }else{//Si el usuario si se autentico por google le generamos su token actualizado y listo puede acceder
                let token = jwt.sign({//Generamos el token con laa info del user usando la lib jwt
                    usuario: usDB
                }, process.env.SEED, { expiresIn: process.env.CADUCIDAD_TOKEN });
                
                return res.json({//Retornamos el usuario con su token recien generado
                    ok:true,
                    usuario:usDB,
                    token
                })
            }
        }else{
            //Si el usuario no existe en nuestra base de datos
            let usuario=new Usuario();
            usuario.nombre=googleUser.nombre;
            usuario.email=googleUser.email;
            usuario.img=googleUser.img;
            usuario.google=true;
            usuario.password=':)';//Ponemos carita feliz por lo que es obligatoria, no deberia poder hacer sesion

            usuario.save((err,usDB)=>{//Guardamos el usuario en nuestra base
                if(err){//Validamos si ubo algun error al momento de guardar en DB
                    return res.status(500).json({
                        ok:false,
                        err
                    })
                }

                let token = jwt.sign({//Generamos el token con la info del user
                    usuario: usDB
                }, process.env.SEED, { expiresIn: process.env.CADUCIDAD_TOKEN });
                
                return res.json({//Retornamos una respuesta ok con la info y token recien generado
                    ok:true,
                    usuario:usDB,
                    token
                })
            })
        }
    });

});



module.exports = app;
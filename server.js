import express, { response } from "express";
import mysql from "mysql";
import cors from "cors";
import jwt, { decode } from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import multer from "multer";

const salt = 10;

const app = express();
const port = 8081;

app.use("/uploads", express.static("Uploads"));
app.use(express.json());
app.use(cors({
  origin:["http://localhost:5173"],
  methods:["POST","GET"],
  credentials:true
} ));
app.use(cookieParser());

const db = mysql.createConnection({
  host: "localhost",
  user: "u143691355_kram",
  password: "9Mihir!12",
  database: "u143691355_kram",
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL server');
});

// Handle MySQL connection errors
db.on('error', (err) => {
  console.error('MySQL connection error:', err);
});

app.get("/", (req, res) => {
  return res.json({ message: "from Backend Side" });
});

app.get("/user", (req, res) => {
  const sql = "SELECT * FROM user";
  db.query(sql, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

app.get("/product", (req, res) => {
  const sql = "SELECT * FROM product";
  db.query(sql, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

app.get("/admin", (req, res) => {
  const sql = "SELECT * FROM admin";
  db.query(sql, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

app.get("/customers", (req, res) => {
  const sql = "SELECT * FROM customers";
  db.query(sql, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});

// Multer setup for handling file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage: storage });

// Route to handle form submissions with file uploads
app.post("/product/addProduct", upload.single("image"), (req, res) => {
  const { name, price, description, likes, discount } = req.body;

  // Assuming the 'image' field in the form is used to upload the image file
  const image = req.file ? req.file.filename : "DefaultImageURL";

  const sql =
    "INSERT INTO `product`(`name`, `price`, `description`, `likes`, `image`, `discount`) VALUES (?, ?, ?, ?, ?,?)";

  db.query(
    sql,
    [name, price, description, likes, image, discount],
    (err, data) => {
      if (err) return res.json(err);
      return res.json(data);
    }
  );
});

const verifyUser = (req, res, next) => {
  const token = req.cookies.token; // Use req.cookies.token instead of req.cookie.token

  if (!token) {
    return res.json({ Error: "error in getting cookies" });
  } else {
    jwt.verify(token, 'jwt-secret-key', (err, decoded) => {
      if (err) {
        return res.json({ Error: "token is not valid" });
      } else {
        req.name = decoded.name;
        next();
      }
    });
  }
}

app.get("http://localhost:8081",verifyUser ,(req,res)=>{
  return response.json({ Status: "Success!",name:res.name });
})

app.post("/register", (req, response) => {
  const sql = "INSERT INTO customers (`name`,`email`, `mobile_number`,`password`, `address`, `gender`) VALUES (?)";

  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return response.json({ Error: "error for hashing password" });

    const values = [req.body.name, req.body.email, req.body.mobile, hash, req.body.address, req.body.gender];

    db.query(sql, [values], (err, res) => {
      if (err)
        return response.json({ Error: "Inserting Data Error in server" });
      return response.json({ Status: "Success!" });
    });
  });
});

app.post('/login', async (req, res) => {
    const sql = 'SELECT * FROM customers WHERE email = ?';

      db.query(sql, [req.body.email], (err, data) => {
        if (err) return console.error('Login error in server:', err);
        if (data.length > 0) {
          bcrypt.compare(req.body.password, data[0].password.toString(), (err, response) => {
            if (err) return res.json({Error: "password compare error on server"});
            if(response){ 
              const name = data[0].name;
              const token = jwt.sign({ name }, 'jwt-secret-key',{expiresIn:'1d'});
              res.cookie("token", token, { httpOnly: true });
              return res.json({ Status: "Success!" });
            }else{
              return res.json({Error:"password not matched on server"});
            }
        })
        }else{
          return res.json({Error:"email not existed on server"});
        }
      });
    });

app.post("/Admin/register", (req, response) => {
  const sql = "INSERT INTO admin (`name`,`email`,`password`) VALUES (?)";

  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return response.json({ Error: "error for hashing password" });

    const values = [req.body.name, req.body.email, hash];

    db.query(sql, [values], (err, res) => {
      if (err)
        return response.json({ Error: "Inserting Data Error in server" });
      return response.json({ Status: "Success!" });
    });
  });
});

app.post('/Admin/login', async (req, res) => {
    const sql = 'SELECT * FROM admin WHERE email = ?';

      db.query(sql, [req.body.email], (err, data) => {
        if (err) return console.error('Login error in server:', err);
        if (data.length > 0) {
          bcrypt.compare(req.body.password, data[0].password.toString(), (err, response) => {
            if (err) return res.json({Error: "password compare error on server"});
            if(response){ 
              return res.json({ Status: "Success!" });
            }else{
              return res.json({Error:"password not matched on server"});
            }
        })
        }else{
          return res.json({Error:"email not existed on server"});
        }
      });
    });

app.listen(process.env.PORT || port, () => {
  console.log(`Server is running on port ${port}`);
});

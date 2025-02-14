// server.js
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const router = express.Router();
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const nodemailer = require('nodemailer');



dotenv.config();

const app = express();
app.set('view engine', 'ejs');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static('src'));
app.use(express.static('public'));

// MongoDB URI
const mongoURI = process.env.MONGODB_URI || 'mongodb+srv://Dhairya:DP492006@projects6.fbt6f4l.mongodb.net/signin?retryWrites=true&w=majority';


// Connect to MongoDB
mongoose.connect(mongoURI)
     .then(() => {
         console.log('Connected to MongoDB');
     })
     .catch((err) => {
         console.error('Failed to connect to MongoDB:', err.message);
     });

// Update session configuration (place this before your routes)
app.use(session({
    secret: '8401288309',
    resave: true,
    saveUninitialized: true,
    store: MongoStore.create({
        mongoUrl: mongoURI,
        ttl: 24 * 60 * 60,
        autoRemove: 'native'
    }),
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true
    },
    name: 'hospitalSession'
}));

// Add this line after session middleware to debug session data
app.use((req, res, next) => {
    console.log('Current Session Data:', {
        id: req.session.hospitalId,
        email: req.session.hospitalEmail,
        isAuthenticated: req.session.isAuthenticated
    });
    next();
});

//TODO login backend code start
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'myprofile.html'));
});

app.post('/login', async (req, res) => {
    try {
        console.log("Login request received.");
        
        console.log("Full request body:", req.body);

        const { email, password } = req.body;

        if (!email) {
            console.log("Email not provided.");
            return res.status(400).send('Please provide both email and password.');
        }

        if (!password) {
            console.log("password not provided.");
            return res.status(400).send('Please provide both email and password.');
        }

        // Check if it's an admin login
        if (email === adminCredentials.email && password === adminCredentials.password) {
        const token = jwt.sign({ email, role: 'admin' }, SECRET_KEY, { expiresIn: '1h' });
        return res.cookie('token', token, { httpOnly: true }).json({ role: 'admin' });
        }

        console.log("Login data received:", { email });

        const user = await User.findOne({ email });
        
        if (!user) {
            console.log("User not found with email:", email);
            return res.status(400).send('Invalid email or password.');
        }
        console.log("User found:", user);

        
        if (!(password === user.password)) {
            console.log("Password mismatch for user:", email);
            return res.status(400).send('Invalid email or password.');
        }
        console.log("Password match confirmed for user:", email);

        // Create session
        req.session.userId = user._id;
        req.session.username = user.username;
        req.session.email = user.email,
        console.log("Session created for user:", req.session);
        res.status(201).redirect('/profile');
       // res.status(200).send('Login successful.');
    } catch (error) {
        console.error("Error during login process:", error);
        res.status(500).send('An error occurred during login.');
    }
});
    
//login backend code end
    
//TODO sign up page backend code start

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    age: { type: Number, required: true },
    gender: { type: String, required: true },
    phone: { type: String, required: true },
    medicalConditions: String,
    medications: String,
    allergies: String,
    emergencyContact: {
        name: { type: String, required: true },
        phone: { type: String, required: true },
        relationship: { type: String, required: true }
    },
    createdAt: { type: Date, default: Date.now },
    profileImage: {
      type: String,
      default: ''
  }
});

const User = mongoose.model('User', userSchema);

// Signup Route
app.post('/api/signup', async (req, res) => {
    console.log('Received signup request:', req.body);

    try {
        const { password, ...userData } = req.body;

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user with the hashed password
        const newUser = new User({ ...userData, password: hashedPassword });
        await newUser.save();

        console.log('User saved successfully:', {
            username: newUser.username,
            email: newUser.email,
            name: `${newUser.firstName} ${newUser.lastName}`
        });

        res.status(201).json({
            message: 'User created successfully',
            userId: newUser._id
        });
    } catch (error) {
        console.error('Error saving user:', error);
        res.status(400).json({
            message: 'Error creating user',
            error: error.message
        });
    }
});

// Serve signup page for root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, 'your-secret-key', (err, user) => {
      if (err) return res.sendStatus(403); // Forbidden
      req.user = user;
      next();
  });
}

// Logout endpoint
app.post('/logout', authenticateToken, (req, res) => {
  // In a real-world scenario, you might want to add the token to a blacklist
  // or implement token invalidation logic here.

  // For now, we'll just send a success response.
  res.status(200).json({ message: 'Logged out successfully' });
});

//Sign up page backend code end

//TODO Profile API, profile page backend code start
app.get('/profile', async (req, res) => {
  try {
      const userEmail = req.session.email;
      if (!userEmail) {
          return res.status(401).json({ message: 'Unauthorized. Please log in.' });
      }

      // Fetch user data
      const user = await User.findOne({ email: userEmail }, '-password');
      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      // Fetch reports for the user and populate the doctor's name
      const reports = await Report.find({ patientEmail: userEmail })
          .populate('doctorId', 'firstName lastName'); // Populate doctor's name

      console.log('Fetched reports:', reports); // Debugging: Check if reports are populated correctly

      // Render the profile page with user data and reports
      res.render('profilepage', { user, reports });
  } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
  }
});

// Configure multer storage for profile images
const profileStorage = multer.diskStorage({
  destination: (req, file, cb) => {
      const dir = 'public/uploads/profiles';
      if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
      }
      cb(null, dir);
  },
  filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const profileUpload = multer({
  storage: profileStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
      const filetypes = /jpeg|jpg|png/;
      const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
      const mimetype = filetypes.test(file.mimetype);
      if (mimetype && extname) {
          return cb(null, true);
      }
      cb(new Error('Only .png, .jpg and .jpeg files are allowed!'));
  }
});

// Add route for profile image upload
app.post('/upload-profile-image', profileUpload.single('profileImage'), async (req, res) => {
  try {
      if (!req.session.email) {
          return res.status(401).json({ message: 'Please login first' });
      }

      if (!req.file) {
          return res.status(400).json({ message: 'No file uploaded' });
      }

      const user = await User.findOne({ email: req.session.email });
      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      // Delete old profile image if exists
      if (user.profileImage) {
          const oldImagePath = path.join(__dirname, 'public', user.profileImage);
          if (fs.existsSync(oldImagePath)) {
              fs.unlinkSync(oldImagePath);
          }
      }

      // Update user's profile image path
      const imagePath = '/uploads/profiles/' + req.file.filename;
      user.profileImage = imagePath;
      await user.save();

      res.json({ 
          success: true, 
          message: 'Profile image updated',
          imagePath: imagePath
      });
  } catch (error) {
      console.error('Error uploading profile image:', error);
      res.status(500).json({ message: 'Error uploading image' });
  }
});
//profile page backend code end

//TODO doctor page backend code start

//doctor schema
const doctorSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  password: String,
  hospital:String,
  expertise: String,
  phoneNumber: String,
  patients: [String],

});

const Doctor = mongoose.model('Doctor', doctorSchema);

// Temporary Doctor Schema
const tempDoctorSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    password: String,
    hospital: String,
    expertise: String,
    phoneNumber: String
});

// Temporary Doctor Model
const TempDoctor = mongoose.model('TempDoctor', tempDoctorSchema);

// Middleware to verify doctor token
const verifyDoctor = async (req, res, next) => {
    try {
        // Request logging
        console.log(`[${new Date().toISOString()}] Verifying doctor session`);
        console.log('Session data:', req.session);

        // Session existence check
        if (!req.session || !req.session.doctorEmail) {
            console.log('No active session or doctor email');
            return res.status(401).json({ 
                status: 'error',
                message: 'Please login first' 
            });
        }

        // Session timeout check
        const sessionAge = Date.now() - req.session.createdAt;
        if (sessionAge > 24 * 60 * 60 * 1000) { // 24 hours
            console.log('Session expired');
            req.session.destroy();
            return res.status(440).json({ 
                status: 'error',
                message: 'Session expired, please login again' 
            });
        }

        // Doctor verification
        const doctor = await Doctor.findOne({ email: req.session.doctorEmail })
                                 .select('-password');
        
        if (!doctor) {
            console.log('Doctor not found:', req.session.doctorEmail);
            return res.status(401).json({ 
                status: 'error',
                message: 'Unauthorized access' 
            });
        }

        // Set security headers
        res.set({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block'
        });

        // Attach doctor data to request
        req.doctor = doctor;
        console.log('Doctor verified:', doctor.email);
        next();
    } catch (error) {
        console.error('Verification error:', error);
        res.status(500).json({ 
            status: 'error',
            message: 'Internal server error' 
        });
    }
};

// Serve static files
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'doclogin.html'));
});

app.get('/docsignin', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'docsignin.html'));
});

app.get('/doctordashboard', (req, res) => {
  res.sendFile(join(__dirname, 'public', 'doctordashboard.html'));
});

//TODO Doctor Routes
app.post('/api/doctor/signup', async (req, res) => {
    try {
        const { firstName, lastName, email, password, hospital, expertise, phoneNumber } = req.body;
        
        // Check if doctor already exists in the temporary collection
        const existingTempDoctor = await TempDoctor.findOne({ email });
        if (existingTempDoctor) {
            return res.status(400).json({ message: 'Doctor already registered. Please complete your KYC.' });
        }
        
        // Check if doctor already exists in the permanent collection
        const existingDoctor = await Doctor.findOne({ email });
        if (existingDoctor) {
            return res.status(400).json({ message: 'Doctor already registered.' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const tempDoctor = new TempDoctor({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            hospital,
            expertise,
            phoneNumber
        });
        
        await tempDoctor.save();
        res.status(201).json({ message: 'Doctor registered successfully. Please complete your KYC.' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

//Doctor Login Route
app.post('/api/doctor/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const doctor = await Doctor.findOne({ email });
        if (!doctor || !(await bcrypt.compare(password, doctor.password))) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Set session variables
        req.session.doctorEmail = doctor.email;
        req.session.doctorId = doctor._id;
        req.session.isDoctor = true;

        res.json({ 
            message: 'Logged in successfully',
            doctor: {
                email: doctor.email,
                firstName: doctor.firstName,
                lastName: doctor.lastName
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/doctor/info', verifyDoctor, async (req, res) => {
  try {
    const doctor = await Doctor.findById(req.doctor._id).select('-password');
    res.json(doctor);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


//route to fetch aptient data on doctor dashboard
// Route to fetch patient data by email
app.get('/api/patient/data', verifyDoctor, async (req, res) => {
    try {
        const { email } = req.query;
        console.log(`Fetching patient data with email: ${email}`);

        const patient = await User.findOne({ email });
        if (!patient) {
            console.log(`Patient not found with email: ${email}`);
            return res.status(404).json({ message: 'Patient not found' });
        }

        console.log(`Patient data retrieved successfully: ${email}`);
        res.json(patient);
    } catch (error) {
        console.error('Error fetching patient data:', error);
        res.status(500).json({ message: error.message });
    }
});
// Report Schema
const reportSchema = new mongoose.Schema({
  patientEmail: { type: String, required: true },
  doctorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true }, // Ensure this references the Doctor model
  diagnosis: { type: String, required: true },
  medicines: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Report = mongoose.model('Report', reportSchema);


// Route to submit a report
app.post('/api/doctor/patient/report', verifyDoctor, async (req, res) => {
    try {
        const { patientEmail, diagnosis, medicines } = req.body;
        const doctorId = req.session.doctorId;

        const report = new Report({
            patientEmail,
            doctorId,
            diagnosis,
            medicines
        });

        await report.save();
        res.json({ message: 'Report submitted successfully' });
    } catch (error) {
        console.error('Error submitting report:', error);
        res.status(500).json({ message: error.message });
    }
});

app.put('/api/doctor/patient/report/:reportId', verifyDoctor, async (req, res) => {
  try {
    const { patientEmail, diagnosis, medicines } = req.body;
    const patient = await User.findOne({ email: patientEmail });
    
    if (!patient) return res.status(404).json({ message: 'Patient not found' });
    
    const report = patient.reports.id(req.params.reportId);
    if (!report) return res.status(404).json({ message: 'Report not found' });
    
    if (report.doctorId.toString() !== req.doctor._id.toString()) {
      return res.status(403).json({ message: 'Not authorized to edit this report' });
    }
    
    report.diagnosis = diagnosis;
    report.medicines = medicines;
    
    await patient.save();
    res.json({ message: 'Report updated successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


async function submitPatientReport() {
    const diagnosis = document.getElementById('diagnosis').value;
    const medicines = document.getElementById('medicines').value;
    
    try {
        const response = await fetch('/api/doctor/patient/report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include', // Ensure cookies are sent with the request
            body: JSON.stringify({
                patientEmail: currentPatientEmail,
                diagnosis,
                medicines
            })
        });
        
        if (response.ok) {
            alert('Report submitted successfully');
            document.getElementById('patientForm').classList.add('hidden');
            document.getElementById('diagnosis').value = '';
            document.getElementById('medicines').value = '';
            currentPatientEmail = '';
            loadPatients();
        } else {
            alert('Error submitting report');
        }
    } catch (error) {
        alert('Error submitting report');
    }
}
app.get('/api/doctor/appointments', verifyDoctor, async (req, res) => {
    try {
        const doctorEmail = req.session.doctorEmail;
        if (!doctorEmail) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        const appointments = await Appointment.find({ doctorEmail });

        if (!appointments.length) {
            return res.json([]); // Return empty array if no appointments
        }

        res.json(appointments);
    } catch (error) {
        console.error('Error fetching appointments:', error);
        res.status(500).json({ message: 'Failed to fetch appointments' });
    }
});


//doctor page backend code end

//TODO Report upload on pateint profile page backend code start
// UpReport Schema
const upReportSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    filename: { type: String, required: true },
    originalName: { type: String, required: true },
    path: { type: String, required: true },
    uploadDate: { type: Date, default: Date.now },
    fileType: { type: String, required: true },
    patientEmail: { type: String, required: true },
    reportType: { type: String, default: 'General' },
    description: String,
    size: Number
});

const UpReport = mongoose.model('UpReport', upReportSchema);

// Multer storage configuration
const reportStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = 'public/uploads/reports';
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'report-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const reportUpload = multer({
    storage: reportStorage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /pdf|doc|docx|jpg|jpeg|png/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('Only .pdf, .doc, .docx, .jpg, .jpeg and .png files are allowed!'));
        }
    }
});

// Upload report route
app.post('/upload-report', reportUpload.single('report'), async (req, res) => {
    try {
        if (!req.session.email) {
            return res.status(401).json({ message: 'Please login first' });
        }

        const user = await User.findOne({ email: req.session.email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const report = new UpReport({
            userId: user._id,
            filename: req.file.filename,
            originalName: req.file.originalname,
            path: '/uploads/reports/' + req.file.filename,
            fileType: path.extname(req.file.originalname).toLowerCase(),
            patientEmail: req.session.email,
            reportType: req.body.reportType || 'General',
            description: req.body.description || '',
            size: req.file.size
        });

        await report.save();

        res.json({
            success: true,
            message: 'Report uploaded successfully',
            report: {
                filename: report.filename,
                originalName: report.originalName,
                path: report.path,
                uploadDate: report.uploadDate,
                reportType: report.reportType
            }
        });

    } catch (error) {
        console.error('Error uploading report:', error);
        res.status(500).json({ 
            message: 'Error uploading report',
            error: error.message 
        });
    }
});

// Get reports route
app.get('/get-reports', async (req, res) => {
  try {
      if (!req.session.email) {
          return res.status(401).json({ message: 'Please login first' });
      }

      const user = await User.findOne({ email: req.session.email });
      if (!user) {
          return res.status(404).json({ message: 'User not found' });
      }

      const reports = await UpReport.find({ userId: user._id })
          .sort({ uploadDate: -1 });
      
      res.json(reports);
  } catch (error) {
      console.error('Error fetching reports:', error);
      res.status(500).json({ 
          message: 'Error fetching reports',
          error: error.message 
      });
  }
});

// Delete report route
app.delete('/delete-report/:reportId', async (req, res) => {
  try {
      if (!req.session.email) {
          return res.status(401).json({ message: 'Please login first' });
      }

      const report = await UpReport.findById(req.params.reportId);
      if (!report) {
          return res.status(404).json({ message: 'Report not found' });
      }

      // Check if user owns the report
      if (report.patientEmail !== req.session.email) {
          return res.status(403).json({ message: 'Unauthorized to delete this report' });
      }

      // Delete file from storage
      const filePath = path.join(__dirname, 'public', report.path);
      if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
      }

      await UpReport.findByIdAndDelete(req.params.reportId);

      res.json({ message: 'Report deleted successfully' });
  } catch (error) {
      console.error('Error deleting report:', error);
      res.status(500).json({ 
          message: 'Error deleting report',
          error: error.message 
      });
  }
});
//Report upload on pateint profile page backend code end


//TODO admin page backend code start
// Secret key for JWT
const SECRET_KEY = '1234567890';

// Middleware for private route authentication
function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Forbidden' });
    req.user = user;
    next();
  });
}

// Admin credentials
const adminCredentials = {
  email: 'admin@email.com',
  password: 'adminSH25',
};

// Login route for admin
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (email === adminCredentials.email && password === adminCredentials.password) {
    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true }).json({ message: 'Login successful' });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Logout route
app.post('/admin/logout', (req, res) => {
  res.clearCookie('token').json({ message: 'Logged out successfully' });
});

// Route: Fetch All Users and Render on HTML Page
app.get("/admin", async (req, res) => {
    try {
        const users = await User.find(); // Retrieve all documents
        console.log("Fetched Users:", users); // Log users to the server console
        res.render("admin", { users }); // Pass users data to EJS template
    } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).send("Internal Server Error");
    }
});

// Route to render the doctors.ejs file
// app.get('/doctors', (req, res) => {
//   res.render('doctors');
//   console.log('Doctors page loaded');
// });

// API endpoint to fetch doctors data
// Add this route to handle doctors page
app.get('/doctors', async (req, res) => {
  try {
      // Fetch all doctors from the database
      const doctors = await Doctor.find({}).select('firstName lastName email hospital expertise phoneNumber patients');
      console.log('Fetched doctors:', doctors); // Debug log
      
      // Render the doctors page with the fetched data
      res.render('doctors', { 
          doctors: doctors,
          title: 'Doctors List'
      });
  } catch (error) {
      console.error('Error fetching doctors:', error);
      res.render('doctors', { 
          doctors: [],
          title: 'Doctors List',
          error: 'Failed to fetch doctors'
      });
  }
});

//*********hospital admin page backend code start********
//2101 i am adding backend for the hospital data to admin page 

// Hospital Schema
const hospitalSchema = new mongoose.Schema({
  email: String,
  password: String,
  hospitalName: String,
  hospitalNumber: String,
  specialty: String,
  numDoctors: Number,
  doctors: [{ name: String, treatment: String }],
  address: String
});

// Hospital Model
const Hospital = mongoose.model('hospitals', hospitalSchema); // Using the collection name 'hospitals'

// Route to Retrieve and Display Hospitals
app.get('/hospital', async (req, res) => {
  try {
      // Fetch data from the database
      const hospitals = await Hospital.find();
      console.log('Fetched Hospitals:', hospitals); // Log the fetched data

      // Render the EJS page with hospital data
      res.render('hospital', { hospitals });
  } catch (error) {
      console.error('Error Fetching Hospitals:', error);
      res.status(500).send('Error retrieving hospitals');
  }
});

//*********hospital admin page backend code end*******

//Admin page backend code end******

//*********hospital backend start*********

//*********hospital backend end*********

// Logout endpoint
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('An error occurred during logout.');
        }
        res.clearCookie('connect.sid'); // clears the session cookie
        res.send('Logout successful.');
    });
});

//TODO ******kyc page backend start********
// Define schemas
const KycSchema = new mongoose.Schema({
    email: String,
    type: String, // 'hospital' or 'doctor'
    files: [String],
    data: mongoose.Schema.Types.Mixed,
});
const KycModel = mongoose.model('Kyc', KycSchema);

// Create storage for Multer
const docsDir = path.join(__dirname, 'docs');
if (!fs.existsSync(docsDir)) {
    fs.mkdirSync(docsDir, { recursive: true });
}

// Configure multer storage
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userEmail = req.body.email;
        if (!userEmail) {
            return cb(new Error('Email is required'));
        }
        
        const userDocsPath = path.join(docsDir, userEmail);
        
        // Create user-specific directory if it doesn't exist
        if (!fs.existsSync(userDocsPath)) {
            fs.mkdirSync(userDocsPath, { recursive: true });
        }
        
        cb(null, userDocsPath);
    },
    filename: function (req, file, cb) {
        // Generate unique filename with original extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// Initialize multer upload
const upload = multer({ 
    storage: storage,
    fileFilter: function (req, file, cb) {
        // Allow only specific file types
        const filetypes = /jpeg|jpg|png|pdf/;
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = filetypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only .jpg, .jpeg, .png and .pdf files are allowed'));
        }
    }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Route for hospital KYC
app.post('/kyc/upload/hospital', upload.fields([
    { name: 'hospitalAadhar', maxCount: 1 },
    { name: 'ownershipProof', maxCount: 1 },
    { name: 'registrationCert', maxCount: 1 },
    { name: 'pharmacyReg', maxCount: 1 },
    { name: 'occupancyCert', maxCount: 1 },
    { name: 'completionCert', maxCount: 1 },
    { name: 'fireNOC', maxCount: 1 },
    { name: 'incomeTaxPAN', maxCount: 1 },
    { name: 'doctorRegistration', maxCount: 1 },
    { name: 'nurseQualifications', maxCount: 1 },
    { name: 'dentistQualifications', maxCount: 1 },
    { name: 'psychologistLicense', maxCount: 1 },
    { name: 'therapistQualifications', maxCount: 1 },
    { name: 'psychiatricLicense', maxCount: 1 },
    { name: 'bloodBankLicense', maxCount: 1 },
    { name: 'mtpRegistration', maxCount: 1 },
]), async (req, res) => {
    try {
        if (!req.files) {
            return res.status(400).json({ success: false, message: 'No files uploaded' });
        }
        const { email, ...formData } = req.body;
        const filePaths = Object.values(req.files).flat().map(file => file.path);

        console.log(`Hospital KYC upload initiated by user: ${email}`);
        console.log(`Files uploaded: ${filePaths.join(', ')}`);

        // Save to database
        const kycRecord = new KycModel({
            email,
            type: 'hospital',
            files: filePaths,
            data: formData,
        });
        await kycRecord.save();
        console.log('Hospital KYC submitted successfully:', kycRecord);
        res.json({ success: true, message: 'Hospital KYC submitted successfully.' });
    } catch (error) {
        console.error('Error saving hospital KYC:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

// Route for doctor KYC
app.post('/kyc/upload/doctor', upload.fields([
    { name: 'doctorAadhar', maxCount: 1 },
    { name: 'pharmacyReg', maxCount: 1 },
    { name: 'occupancyCert', maxCount: 1 },
    { name: 'completionCert', maxCount: 1 }
]), async (req, res) => {
    try {
        if (!req.files) {
            return res.status(400).json({ success: false, message: 'No files uploaded' });
        }
        const { email, ...formData } = req.body;
        const filePaths = Object.values(req.files).flat().map(file => file.path);

        console.log(`Doctor KYC upload initiated by user: ${email}`);
        console.log(`Files uploaded: ${filePaths.join(', ')}`);

        // Save to database
        const kycRecord = new KycModel({
            email,
            type: 'doctor',
            files: filePaths,
            data: formData,
        });
        await kycRecord.save();
        console.log('Doctor KYC submitted successfully:', kycRecord);
        res.json({ success: true, message: 'Doctor KYC submitted successfully.' });
    } catch (error) {
        console.error('Error saving doctor KYC:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

// Route to approve KYC request
app.post('/admin/kyc/approve/:id', async (req, res) => {
    try {
        const kycRequest = await KycModel.findById(req.params.id);
        if (!kycRequest) {
            return res.status(404).json({ success: false, message: 'KYC request not found' });
        }

        // Save to respective collection
        if (kycRequest.type === 'hospital') {
            const hospital = new Hospital({
                email: kycRequest.email,
                files: kycRequest.files,
                data: kycRequest.data,
            });
            await hospital.save();
        } else if (kycRequest.type === 'doctor') {
            const tempDoctor = await TempDoctor.findOne({ email: kycRequest.email });
            if (!tempDoctor) {
                return res.status(404).json({ success: false, message: 'Temporary doctor data not found' });
            }

            const doctor = new Doctor({
                firstName: tempDoctor.firstName,
                lastName: tempDoctor.lastName,
                email: tempDoctor.email,
                password: tempDoctor.password,
                hospital: tempDoctor.hospital,
                expertise: tempDoctor.expertise,
                phoneNumber: tempDoctor.phoneNumber
            });
            await doctor.save();
            await TempDoctor.findByIdAndDelete(tempDoctor._id);
        }

        // Delete the KYC request after approval
        await KycModel.findByIdAndDelete(req.params.id);
        res.redirect('/admin/kycrequests');
    } catch (error) {
        console.error('Error approving KYC request:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

// Route to reject KYC request
app.post('/admin/kyc/reject/:id', async (req, res) => {
    try {
        await KycModel.findByIdAndDelete(req.params.id);
        res.redirect('/admin/kycrequests');
    } catch (error) {
        console.error('Error rejecting KYC request:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

// Serve static files
app.use('/docs', express.static(path.join(__dirname, 'docs')));

// Route to render KYC requests page
app.get('/admin/kycrequests', async (req, res) => {
    try {
        const kycRequests = await KycModel.find();
        res.render('kycrequests', { kycRequests });
    } catch (error) {
        console.error('Error fetching KYC requests:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

//******kyc page backend end******
//TODO contact support backend start (admin)

// Define the schema
const contactSchema = new mongoose.Schema({
    email: String,
    message: String,
  });
  
  const replySchema = new mongoose.Schema({
    complaintId: mongoose.Schema.Types.ObjectId, // Reference to Contact document
    reply: String,
    email: String, // For easier tracking
  });
  
  // Mongoose models
  const Contact = mongoose.model("contacts", contactSchema); // 'contacts' collection
  const ComplaintReply = mongoose.model("complaints", replySchema); // 'complaints' collection
  
  app.get("/admin/complaints", async (req, res) => {
    try {
      const complaints = await Contact.find(); // Pending complaints
      const replied = await ComplaintReply.find(); // Replied complaints
      res.render("complaints", { complaints, replied });
    } catch (error) {
      console.error("Error fetching complaints:", error);
      res.status(500).send("Error fetching complaints.");
    }
  });
  
  app.post("/admin/complaints/reply", async (req, res) => {
    try {
      const { id, reply } = req.body;
  
      if (!id || !reply) {
        return res.status(400).json({ success: false, message: "Missing complaint ID or reply." });
      }
  
      const complaint = await Contact.findById(id);
      if (!complaint) {
        return res.status(404).json({ success: false, message: "Complaint not found." });
      }
  
      const newReply = new ComplaintReply({
        complaintId: id,
        reply,
        email: complaint.email,
      });
      await newReply.save();
  
      await Contact.findByIdAndDelete(id); // Remove from pending complaints
  
      // Nodemailer
      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: "safeharbour108@gmail.com",
          pass: "kngl uiyl gacw lzvy",
        },
      });
  
      const mailOptions = {
        from: "safeharbour108@gmail.com",
        to: complaint.email,
        subject: "Reply to Your Complaint",
        text: reply,
      };
  
      await transporter.sendMail(mailOptions);
  
      res.json({ success: true, message: "Reply sent and stored successfully!" });
    } catch (error) {
      console.error("Error replying to complaint:", error);
      res.status(500).json({ success: false, message: "Error replying to complaint." });
    }
  });
  

//contact support backend End (admin)

//contact support backend start (user)

//TODO Route to handle form submission (POST /contactus)
app.post('/contactus', async (req, res) => {
    const { email, message } = req.body;

    console.log('Received request body:', req.body); // Debug log

    try {
        // Validate input data
        if ( !email || !message) {
            return res.status(400).json({ error: 'All fields are required.' });
        }

        // Create and save the new Contact document
        const newContact = new Contact({ email, message });
        const savedContact = await newContact.save();

        // Log a success message in the console
        console.log('Your data is saved:', savedContact);

        // Return a success response to the client
        res.status(200).json({ message: 'Data saved successfully', data: savedContact });
    } catch (error) {
        console.error('Error saving data:', error.message);
        res.status(500).json({ error: 'Error saving data. Please try again later.' });
    }
});
//Contact us backend end(user)

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`http://localhost:${port}`);
});
// Appointment Schema
const appointmentSchema = new mongoose.Schema({
  patientName: String,
  patientEmail: String,
  doctorName: String,
  doctorEmail: String,
  date: String,
  time: String,
  reference: String,
});

const Appointment = mongoose.model("Appointment", appointmentSchema);

// GET Route: Display Appointment Form + Check for Existing Appointment
app.get("/appointment", async (req, res) => {
  try {
    const doctors = await Doctor.find({}, "firstName lastName email expertise");

    // Fetch the latest appointment for this session user (if any)
    const patientEmail = req.session.patientEmail || null;
    let existingAppointment = null;

    if (patientEmail) {
      existingAppointment = await Appointment.findOne({ patientEmail });
    }

    const doctorList = doctors.map((doctor) => ({
      id: doctor._id,
      name: `${doctor.firstName} ${doctor.lastName}`,
      email: doctor.email,
      specialty: doctor.expertise,
    }));

    res.render("appointment", { doctors: doctorList, existingAppointment });
  } catch (err) {
    console.error("Error fetching doctors:", err);
    res.status(500).send("An error occurred while loading doctors.");
  }
});

// POST Route: Book Appointment
app.post("/appointment", async (req, res) => {
  const { patientName, patientEmail, doctorId, date, time, reference } = req.body;

  try {
    const selectedDoctor = await Doctor.findById(doctorId);

    if (!selectedDoctor) {
      return res.status(404).send("Selected doctor not found.");
    }

    // Save appointment in the database
    const newAppointment = new Appointment({
      patientName,
      patientEmail,
      doctorName: `${selectedDoctor.firstName} ${selectedDoctor.lastName}`,
      doctorEmail: selectedDoctor.email,
      date,
      time,
      reference,
    });

    await newAppointment.save();

    // Store patient email in session for checking existing appointment
    req.session.patientEmail = patientEmail;

    // Add patient reference in doctor's record
    selectedDoctor.patients.push({ name: patientName, email: patientEmail, date, time, reference });
    await selectedDoctor.save();

    res.redirect("/appointment");
  } catch (err) {
    console.error("Error booking appointment:", err);
    res.status(500).send("An error occurred while booking the appointment.");
  }
});

// POST Route: Cancel Appointment
app.post("/cancel-appointment", async (req, res) => {
  const { patientEmail } = req.body;

  try {
    // Find and delete the appointment
    const deletedAppointment = await Appointment.findOneAndDelete({ patientEmail });

    if (!deletedAppointment) {
      return res.status(404).send("Appointment not found.");
    }

    // Remove patient from doctor's patient list
    await Doctor.updateOne(
      { email: deletedAppointment.doctorEmail },
      { $pull: { patients: { email: patientEmail } } }
    );

    // Clear session
    req.session.patientEmail = null;

    res.redirect("/appointment");
  } catch (err) {
    console.error("Error canceling appointment:", err);
    res.status(500).send("An error occurred while canceling the appointment.");
  }
});


  
  // Appointment Schema
  const h_appointmentSchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    doctor: String,
    date: String,
    message: String,
  });
  
  const h_Appointment = mongoose.model("h_appointments", h_appointmentSchema, "h_appointments");
  
  // Contact Schema
  const h_contactSchema = new mongoose.Schema({
    name: String,
    email: String,
    message: String,
    createdAt: { type: Date, default: Date.now }
  });
  const h_Contact = mongoose.model("h_contacts", h_contactSchema, "h_contacts");
  
  // Routes
  
  // Signup Route (GET & POST)
  app.route("/h_signup")
    .get((req, res) => res.render("h_signup", { errorMessage: null }))
    .post(async (req, res) => {
      const {
        email,
        password,
        confirmPassword,
        hospitalName,
        hospitalNumber,
        specialty,
        numDoctors,
        doctorNames,
        doctorTreatments,
        address,
      } = req.body;
  
      if (password !== confirmPassword) {
        return res.render("h_signup", { errorMessage: "Passwords do not match" });
      }
  
      if (!doctorNames || !doctorTreatments || doctorNames.length !== doctorTreatments.length) {
        return res.render("h_signup", { errorMessage: "Doctor names and treatments must be provided and have the same number." });
      }
  
      const doctors = doctorNames.map((name, index) => ({
        name: name,
        treatment: doctorTreatments[index],
      }));
  
      const newHospital = new Hospital({
        email,
        password,
        hospitalName,
        hospitalNumber,
        specialty,
        numDoctors,
        doctors,
        address,
      });
  
      try {
        await newHospital.save();
        console.log("Data successfully stored");
        res.redirect("/login");
      } catch (err) {
        console.error("Error storing data:", err);
        res.status(500).send("An error occurred while saving the data.");
      }
    });
  
  // Login Route (GET & POST)
  app.route("/h_login")
    .get((req, res) => res.render("h_login", { errorMessage: null }))
    .post(async (req, res) => {
      const { email, password } = req.body;
      const hospital = await Hospital.findOne({ email, password });
  
      if (!hospital) {
        return res.render("h_login", { errorMessage: "Invalid email or password" });
      }
  
      req.session.hospitalId = hospital._id;
      res.redirect("/h_profile");
    });
  
  // Profile Routes
  app.get("/h_profile", async (req, res) => {
    if (!req.session.hospitalId) return res.redirect("/h_login");
    const hospital = await Hospital.findById(req.session.hospitalId);
    if (!hospital) return res.redirect("/h_login");
    res.render("h_profile", { hospital });
  });
  
  app.route("/edit-profile")
    .get(async (req, res) => {
      if (!req.session.hospitalId) return res.redirect("/h_login");
      const hospital = await Hospital.findById(req.session.hospitalId);
      if (!hospital) return res.redirect("/h_login");
      res.render("edit-profile", { hospital });
    })
    .post(async (req, res) => {
      if (!req.session.hospitalId) return res.redirect("/h_login");
      const {
        hospitalName,
        email,
        password,
        confirmPassword,
        hospitalNumber,
        specialty,
        numDoctors,
        address,
        doctorNames,
        doctorTreatments,
      } = req.body;
  
      if (!doctorNames || !doctorTreatments || doctorNames.length !== doctorTreatments.length) {
        return res.status(400).send("Doctor names and treatments must match in number.");
      }
  
      if (password && password !== confirmPassword) {
        return res.status(400).send("Passwords do not match.");
      }
  
      const updatedDoctors = doctorNames.map((name, index) => ({ name, treatment: doctorTreatments[index] }));
  
      const updateData = { hospitalName, email, hospitalNumber, specialty, numDoctors: parseInt(numDoctors, 10), address, doctors: updatedDoctors };
      if (password) updateData.password = password;
  
      await Hospital.findByIdAndUpdate(req.session.hospitalId, updateData);
      res.redirect("/h_profile");
    });
  
  // Logout
  app.get("/h_logout", (req, res) => {
    req.session.destroy(() => res.redirect("/h_login"));
  });
  
  // Hospital Dashboard
  app.get("/h_dashboard", async (req, res) => {
    try {
      const h_appointments = await h_Appointment.find({});
      res.render("h_dashboard", { h_appointments });
    } catch (err) {
      console.error("Error fetching appointments:", err);
      res.status(500).send("An error occurred while fetching appointments.");
    }
  });
  
  // Appointment Routes
  // Appointment Route (GET)
  app.get("/h_appointments", async (req, res) => {
    try {
      // Fetch appointments from the database
      const h_appointments = await h_Appointment.find({});
      res.render("h_appointments", { h_appointments }); // Make sure you have a corresponding EJS file
    } catch (err) {
      console.error("Error fetching appointments:", err);
      res.status(500).send("An error occurred while fetching appointments.");
    }
  });
  
  
  // Hospital Contact Us Route (GET & POST)
  app.route("/h_contactus")
    .get((req, res) => {
      res.render("h_contactus", { errorMessage: null, successMessage: null });
    })
    .post(async (req, res) => {
      const { name, email, message } = req.body;
  
      if (!name || !email || !message) {
        return res.render("h_contactus", { 
          errorMessage: "All fields are required.", 
          successMessage: null 
        });
      }
  
      try {
        const newContact = new h_Contact({ name, email, message });
        await newContact.save();
        console.log("New contact message saved:", newContact);
  
        res.render("h_contactus", { 
          errorMessage: null, 
          successMessage: "Thank you for reaching out! We will get back to you soon." 
        });
      } catch (err) {
        console.error("Error saving contact message:", err);
        res.status(500).render("hospital-contactus", { 
          errorMessage: "An error occurred while submitting your message. Please try again later.", 
          successMessage: null 
        });
      }
    });
  
  // Define Transaction Schema & Model
  const transactionSchema = new mongoose.Schema({
    merchantName: String,
    cardholderName: String,
    mySafeID: String,
    contactNumber: String,
    dob: String,
    address: String
  });
  const Transaction = mongoose.model("transactions", transactionSchema, "transactions");
  
  // Define Routes
  
  // Default Route - Dashboard
  app.get('/h_home', async (req, res) => {
    try {
        const transactions = await Transaction.find();  // Fetch transactions from the database
        res.render('h_home', { transactions });  // Pass transactions to the EJS template
    } catch (err) {
        console.error("Error fetching transactions:", err);
        res.status(500).send('Server Error');
    }
  });
  
  
  // Redirect `/home` to `/hospital-home`
  app.get('/h_home', (req, res) => {
  res.redirect('/h_home');
  });
  
  // Hospital Home Route
  app.get('/h_home', async (req, res) => {
  try {
      res.render('h_home');  // Ensure 'hospital-home.ejs' exists in 'views' folder
  } catch (err) {
      console.error("Error rendering hospital-home:", err);
      res.status(500).send('Server Error');
  }
  });
  
  // API Route to Delete Transaction
  app.delete('/api/transactions/:id', async (req, res) => {
  try {
      await Transaction.findByIdAndDelete(req.params.id);
      res.status(200).json({ message: 'Transaction deleted successfully' });
  } catch (err) {
      console.error("Error deleting transaction:", err);
      res.status(500).json({ error: 'Error deleting transaction' });
  }
  });


// Simplified checkHospitalSession middleware


//TODO Hospita login
app.post('/h_login', async (req, res) => {
    console.log('\n=== Processing Hospital Login ===');
    const { email, password } = req.body;

    try {
        // Find hospital in database
        const hospital = await Hospital.findOne({ email, password });
        
        if (!hospital) {
            console.log('❌ Invalid login attempt:', email);
            return res.render('h_login', { 
                errorMessage: 'Invalid email or password' 
            });
        }

        console.log('✅ Login successful:', email);
      

        res.redirect('/h_dashboard');
    } catch (error) {
        console.error('❌ Login error:', error);
        return res.render('h_login', { 
            errorMessage: 'An error occurred during login' 
        });
    }
});



// Add this middleware before the NFC routes


// NFC Check-in Schema
const nfcCheckInSchema = new mongoose.Schema({
    email: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    name: String,
    age: Number,
    gender: String,
    phone: String,
    location: String,
    department: String,
    medicalConditions: String,
    medications: String,
    allergies: String,
    emergencyContact: {
        name: String,
        phone: String,
        relationship: String
    }
});

const NfcCheckIn = mongoose.model('NfcCheckIn', nfcCheckInSchema);

// NFC Check-in routes with detailed logging
app.get('/nfc-checkins/:email', async (req, res) => {
  console.log('\n=== Starting NFC Check-in Process ===');
  console.log(`Timestamp: ${new Date().toISOString()}`);
  console.log(`Requesting check-in form for email: ${req.params.email}`);
  
  try {
      const { email } = req.params;
      
      console.log('Searching for user in database...');
      const user = await User.findOne({ email });
      
      if (!user) {
          console.log('❌ User not found in database');
          return res.status(404).render('error', { message: 'User not found' });
      }

      console.log('✅ User found in database:');
      console.log({
          name: `${user.firstName} ${user.lastName}`,
          email: user.email,
          age: user.age,
          gender: user.gender
      });

      console.log('Rendering check-in form with user data...');
      res.render('nfc-checkins', { user });

  } catch (error) {
      console.error('❌ Server error during form retrieval:', error);
      res.status(500).render('error', { message: 'Internal server error' });
  }
});

app.post('/nfc-checkins', async (req, res) => {
  console.log('\n=== Processing NFC Check-in Submission ===');
  console.log(`Timestamp: ${new Date().toISOString()}`);
  
  try {
      const {
          email, location, department,
          firstName, lastName, age, gender, phone,
          medicalConditions, medications, allergies,
          emergencyContactName, emergencyContactPhone, emergencyContactRelation
      } = req.body;

      console.log('Received check-in data:');
      console.log({
          email,
          location,
          department,
          patientName: `${firstName} ${lastName}`,
          timestamp: new Date().toISOString()
      });

      console.log('Creating new check-in record...');
      const newCheckIn = new NfcCheckIn({
          email,
          timestamp: new Date(),
          name: `${firstName} ${lastName}`,
          age, gender, phone,
          location, department,
          medicalConditions, medications, allergies,
          emergencyContact: {
              name: emergencyContactName,
              phone: emergencyContactPhone,
              relationship: emergencyContactRelation
          }
      });

      console.log('Saving check-in to database...');
      await newCheckIn.save();
      console.log('✅ Check-in saved successfully!');
      console.log('Check-in details:', newCheckIn);

      console.log('Redirecting to recent check-ins page...');
      res.redirect('/recent-checkins');
  } catch (error) {
      console.error('❌ Error during check-in process:', error);
      res.status(500).render('error', { message: 'Error saving check-in' });
  }
});

app.get('/recent-checkins', async (req, res) => {
  console.log('\n=== Fetching Recent Check-ins ===');
  console.log(`Timestamp: ${new Date().toISOString()}`);
  
  try {
      console.log('Querying database for recent check-ins...');
      const checkins = await NfcCheckIn.find()
          .sort({ timestamp: -1 })
          .limit(50);

      console.log(`✅ Found ${checkins.length} recent check-ins`);
      console.log('Most recent check-in:', checkins[0]);

      console.log('Rendering recent-checkins page...');
      res.render('recent-checkins', { checkins: checkins });
  } catch (error) {
      console.error('❌ Error fetching check-ins:', error);
      res.status(500).render('error', { 
          message: 'Error fetching check-ins',
          error: error
      });
  }
});



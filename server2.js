const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Use session middleware
app.use(
  session({
    secret: "yourSecretKey",
    resave: false,
    saveUninitialized: true,
  })
);

// Set up views directory and view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// MongoDB connection
const MONGODB_URI = "mongodb+srv://Dhairya:DP492006@projects6.fbt6f4l.mongodb.net/signin?retryWrites=true&w=majority&tls=true";
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Doctor Schema
const doctorSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  password: String,
  hospital: String,
  expertise: String,
  phoneNumber: String,
  patients: [{ name: String, email: String, date: String, time: String, reference: String }],
});

const Doctor = mongoose.model("Doctor", doctorSchema);

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

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { createRemoteJWKSet, jwtVerify } = require("jose-cjs");

dotenv.config();

const app = express();
const port = process.env.PORT || 8541;

app.use(cors({
  origin: [
    process.env.CLIENT_URL || "http://localhost:3000",
    "http://localhost:3000",
    "http://localhost:3001"
  ],
  credentials: true,
}));
app.use(express.json());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const clientUrl = process.env.CLIENT_URL || "http://localhost:3000";
const JWKS = createRemoteJWKSet(new URL(`${clientUrl}/api/auth/jwks`));

const toMongoId = (id) => {
  try {
    if (ObjectId.isValid(id) && String(new ObjectId(id)) === id) {
      return new ObjectId(id);
    }
    return id;
  } catch {
    return id;
  }
};

const idFilter = (id) => {
  const mongoId = toMongoId(id);
  if (mongoId instanceof ObjectId) {
    return { $or: [{ _id: mongoId }, { _id: id }] };
  }
  return { _id: id };
};

const db = client.db(process.env.DB_NAME || "Takebul-Islam");
const projectsCollection = db.collection("projects");
const messagesCollection = db.collection("messages");
const usersCollection = db.collection("user");

// Ensure admin user role in DB on startup
async function ensureAdminUser() {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || "takebulislam@gmail.com";
    const user = await usersCollection.findOne({ email: adminEmail });
    if (user && user.role !== "admin") {
      await usersCollection.updateOne(
        { email: adminEmail },
        { $set: { role: "admin", updatedAt: new Date().toISOString() } }
      );
      console.log(`[AUTH] Successfully updated ${adminEmail} to admin role.`);
    }
  } catch (err) {
    console.warn("[AUTH] Could not verify admin user on start:", err.message);
  }
}
ensureAdminUser();

// Token & Admin Authorization Middleware
const verifyAdmin = async (req, res, next) => {
  const authHeader = req.headers.authorization || req.headers.Authorization;

  if (!authHeader) {
    return res.status(401).json({ success: false, message: "Unauthorized access: No token provided" });
  }

  const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;

  if (!token) {
    return res.status(401).json({ success: false, message: "Unauthorized access: Malformed token" });
  }

  try {
    const { payload } = await jwtVerify(token, JWKS);
    const adminEmail = process.env.ADMIN_EMAIL || "takebulislam@gmail.com";
    const userEmail = payload.email;

    // Check payload role or email
    if (payload.role === "admin" || userEmail === adminEmail) {
      req.user = payload;
      return next();
    }

    // Check database user document
    const userId = payload.sub || payload.id;
    const dbUser = await usersCollection.findOne({
      $or: [
        { email: userEmail },
        idFilter(userId)
      ]
    });

    if (dbUser && (dbUser.role === "admin" || dbUser.email === adminEmail)) {
      req.user = dbUser;
      return next();
    }

    return res.status(403).json({ success: false, message: "Forbidden: Admin privileges required" });
  } catch (error) {
    console.error("[AUTH] Token verification failed:", error.message);
    return res.status(403).json({ success: false, message: "Forbidden: Invalid or expired token" });
  }
};

// Root Health Check
app.get("/", (req, res) => {
  res.json({
    status: "online",
    service: "Takebul Islam Portfolio REST API",
    version: "1.0.0",
    time: new Date().toISOString()
  });
});

// GET /projects - Public projects listing
app.get("/projects", async (req, res) => {
  try {
    const { featured, category, status, search } = req.query;
    const query = {};

    // Default to published unless specified
    if (status && status !== "all") {
      query.status = status;
    } else if (!status) {
      query.status = "published";
    }

    if (featured === "true") {
      query.featured = true;
    }

    if (category && category !== "All" && category !== "all") {
      query.category = { $regex: new RegExp(`^${category}$`, "i") };
    }

    if (search && search.trim()) {
      const searchRegex = { $regex: search.trim(), $options: "i" };
      query.$or = [
        { title: searchRegex },
        { shortDescription: searchRegex },
        { description: searchRegex },
        { technologies: searchRegex },
      ];
    }

    const projects = await projectsCollection
      .find(query)
      .sort({ order: 1, createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      count: projects.length,
      data: projects
    });
  } catch (error) {
    console.error("Error fetching projects:", error);
    res.status(500).json({ success: false, message: "Failed to fetch projects" });
  }
});

// GET /projects/admin/all - Admin projects listing with stats
app.get("/projects/admin/all", verifyAdmin, async (req, res) => {
  try {
    const projects = await projectsCollection
      .find({})
      .sort({ order: 1, createdAt: -1 })
      .toArray();

    const stats = {
      total: projects.length,
      published: projects.filter(p => p.status === "published").length,
      draft: projects.filter(p => p.status === "draft").length,
      featured: projects.filter(p => p.featured === true).length,
    };

    res.json({
      success: true,
      stats,
      data: projects
    });
  } catch (error) {
    console.error("Error fetching admin projects:", error);
    res.status(500).json({ success: false, message: "Failed to fetch admin projects" });
  }
});

// GET /projects/:slug - Single project details
app.get("/projects/:slug", async (req, res) => {
  try {
    const { slug } = req.params;
    let project = await projectsCollection.findOne({ slug });

    // Fallback: search by _id if not found by slug
    if (!project) {
      project = await projectsCollection.findOne(idFilter(slug));
    }

    if (!project) {
      return res.status(404).json({ success: false, message: "Project not found" });
    }

    res.json({
      success: true,
      data: project
    });
  } catch (error) {
    console.error("Error fetching project by slug:", error);
    res.status(500).json({ success: false, message: "Failed to fetch project details" });
  }
});

// Helper for generating slugs
const generateSlug = (text) => {
  return text
    .toString()
    .toLowerCase()
    .trim()
    .replace(/[\s\W-]+/g, "-")
    .replace(/^-+|-+$/g, "");
};

// POST /projects - Create a new project (Admin Only)
app.post("/projects", verifyAdmin, async (req, res) => {
  try {
    const body = req.body;

    if (!body.title || !body.shortDescription) {
      return res.status(400).json({
        success: false,
        message: "Title and Short Description are required"
      });
    }

    let slug = body.slug ? generateSlug(body.slug) : generateSlug(body.title);
    // Ensure slug uniqueness
    const existingSlug = await projectsCollection.findOne({ slug });
    if (existingSlug) {
      slug = `${slug}-${Date.now().toString().slice(-4)}`;
    }

    const toArray = (val) => {
      if (Array.isArray(val)) return val.filter(Boolean);
      if (typeof val === "string") return val.split(",").map(s => s.trim()).filter(Boolean);
      return [];
    };

    const newProject = {
      title: body.title.trim(),
      slug,
      shortDescription: body.shortDescription.trim(),
      description: (body.description || body.shortDescription).trim(),
      category: body.category || "Full-Stack",
      featured: Boolean(body.featured),
      status: body.status || "published",
      thumbnail: body.thumbnail || "https://images.unsplash.com/photo-1555066931-4365d14bab8c?w=1200&auto=format&fit=crop&q=80",
      images: toArray(body.images).length > 0 ? toArray(body.images) : [body.thumbnail || "https://images.unsplash.com/photo-1555066931-4365d14bab8c?w=1200&auto=format&fit=crop&q=80"],
      technologies: toArray(body.technologies),
      frontendRepository: body.frontendRepository || "",
      backendRepository: body.backendRepository || "",
      liveUrl: body.liveUrl || "",
      clientType: body.clientType || "Production Application",
      projectType: body.projectType || "Full-Stack Web Application",
      role: body.role || "Full-Stack Web Developer",
      duration: body.duration || "2 Months",
      startDate: body.startDate || "",
      endDate: body.endDate || "",
      keyFeatures: toArray(body.keyFeatures),
      technicalChallenges: toArray(body.technicalChallenges),
      solutions: toArray(body.solutions),
      architecture: body.architecture || "",
      lessonsLearned: toArray(body.lessonsLearned),
      order: Number(body.order) || 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const result = await projectsCollection.insertOne(newProject);
    newProject._id = result.insertedId;

    res.status(201).json({
      success: true,
      message: "Project created successfully",
      data: newProject
    });
  } catch (error) {
    console.error("Error creating project:", error);
    res.status(500).json({ success: false, message: "Failed to create project" });
  }
});

// PATCH /projects/:id - Update project (Admin Only)
app.patch("/projects/:id", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const body = { ...req.body };
    delete body._id; // Prevent updating immutable _id

    const toArray = (val) => {
      if (Array.isArray(val)) return val.filter(Boolean);
      if (typeof val === "string") return val.split(",").map(s => s.trim()).filter(Boolean);
      return undefined;
    };

    if (body.technologies !== undefined) body.technologies = toArray(body.technologies);
    if (body.keyFeatures !== undefined) body.keyFeatures = toArray(body.keyFeatures);
    if (body.technicalChallenges !== undefined) body.technicalChallenges = toArray(body.technicalChallenges);
    if (body.solutions !== undefined) body.solutions = toArray(body.solutions);
    if (body.lessonsLearned !== undefined) body.lessonsLearned = toArray(body.lessonsLearned);
    if (body.images !== undefined) body.images = toArray(body.images);
    if (body.order !== undefined) body.order = Number(body.order) || 0;
    if (body.featured !== undefined) body.featured = Boolean(body.featured);

    body.updatedAt = new Date().toISOString();

    const result = await projectsCollection.findOneAndUpdate(
      idFilter(id),
      { $set: body },
      { returnDocument: "after" }
    );

    if (!result) {
      return res.status(404).json({ success: false, message: "Project not found" });
    }

    res.json({
      success: true,
      message: "Project updated successfully",
      data: result
    });
  } catch (error) {
    console.error("Error updating project:", error);
    res.status(500).json({ success: false, message: "Failed to update project" });
  }
});

// DELETE /projects/:id - Delete project (Admin Only)
app.delete("/projects/:id", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await projectsCollection.deleteOne(idFilter(id));

    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, message: "Project not found" });
    }

    res.json({
      success: true,
      message: "Project deleted successfully"
    });
  } catch (error) {
    console.error("Error deleting project:", error);
    res.status(500).json({ success: false, message: "Failed to delete project" });
  }
});

// POST /messages - Submit contact message (Public)
app.post("/messages", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !message) {
      return res.status(400).json({
        success: false,
        message: "Name, email, and message are required"
      });
    }

    const newMessage = {
      name: name.trim(),
      email: email.trim().toLowerCase(),
      subject: (subject || "General Inquiry").trim(),
      message: message.trim(),
      read: false,
      createdAt: new Date().toISOString()
    };

    const result = await messagesCollection.insertOne(newMessage);
    newMessage._id = result.insertedId;

    res.status(201).json({
      success: true,
      message: "Message received. Thank you for getting in touch!",
      data: newMessage
    });
  } catch (error) {
    console.error("Error submitting contact message:", error);
    res.status(500).json({ success: false, message: "Failed to send message" });
  }
});

// GET /messages - View messages (Admin Only)
app.get("/messages", verifyAdmin, async (req, res) => {
  try {
    const messages = await messagesCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      count: messages.length,
      data: messages
    });
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ success: false, message: "Failed to fetch messages" });
  }
});

// PATCH /messages/:id/read - Mark message read status (Admin Only)
app.patch("/messages/:id/read", verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { read } = req.body;

    const result = await messagesCollection.updateOne(
      idFilter(id),
      { $set: { read: read !== undefined ? Boolean(read) : true } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ success: false, message: "Message not found" });
    }

    res.json({ success: true, message: "Message status updated" });
  } catch (error) {
    console.error("Error updating message status:", error);
    res.status(500).json({ success: false, message: "Failed to update message" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});


const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const dotenv = require('dotenv');

dotenv.config();
const app = express();

// ==================== SECURITY MIDDLEWARE ====================
app.use(helmet());

// CORS configuration - allow both local and live
app.use(cors({
    origin: [
        'http://localhost:3000',
        'http://localhost:5000',
        'https://megatools-dashboard-test.netlify.app',
        /\.netlify\.app$/
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: process.env.RATE_LIMIT_WINDOW * 60 * 1000,
    max: process.env.RATE_LIMIT_MAX,
    message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ==================== MongoDB CONNECTION ====================
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected Successfully'))
.catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1);
});

// ==================== SCHEMAS ====================

// User Schema
const UserSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: [true, 'Username is required'], 
        unique: true,
        trim: true,
        minlength: [3, 'Username must be at least 3 characters'],
        maxlength: [20, 'Username cannot exceed 20 characters']
    },
    fullName: { 
        type: String, 
        required: [true, 'Full name is required'],
        trim: true 
    },
    email: { 
        type: String, 
        required: [true, 'Email is required'], 
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    password: { 
        type: String, 
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters']
    },
    phone: { 
        type: String, 
        default: '',
        trim: true 
    },
    facebook: { 
        type: String, 
        default: '',
        trim: true 
    },
    role: { 
        type: String, 
        enum: ['admin', 'moderator', 'user'], 
        default: 'user' 
    },
    status: { 
        type: String, 
        enum: ['pending', 'active', 'blocked', 'deleted'], 
        default: 'pending' 
    },
    masterId: { 
        type: String, 
        required: true, 
        unique: true 
    },
    referralCode: { 
        type: String, 
        required: true, 
        unique: true 
    },
    referredBy: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User' 
    },
    profilePicture: { 
        type: String, 
        default: '' 
    },
    credits: {
        type: Number,
        default: 0
    },
    lastLogin: { 
        type: Date 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    },
    updatedAt: { 
        type: Date 
    }
});

// Campaign Schema
const CampaignSchema = new mongoose.Schema({
    name: { 
        type: String, 
        required: [true, 'Campaign name is required'],
        trim: true 
    },
    description: {
        type: String,
        default: ''
    },
    icon: { 
        type: String, 
        default: 'fa-globe' 
    },
    color_class: { 
        type: String, 
        default: 'bg-indigo-600' 
    },
    current_domain: { 
        type: String, 
        required: [true, 'Domain is required'],
        trim: true 
    },
    steps: [{
        name: { 
            type: String, 
            enum: ['Entry Action', 'Quick Action', 'Switch Page', 'More page'], 
            required: true 
        },
        path: { 
            type: String, 
            required: true 
        },
        description: String
    }],
    imageUrl: { 
        type: String, 
        default: '' 
    },
    ownerId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    isActive: {
        type: Boolean,
        default: true
    },
    clicks: {
        type: Number,
        default: 0
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    },
    updatedAt: { 
        type: Date 
    }
});

// Click Schema
const ClickSchema = new mongoose.Schema({
    campaignId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Campaign', 
        required: true 
    },
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User' 
    },
    clickedAt: { 
        type: Date, 
        default: Date.now 
    },
    device: { 
        type: String, 
        enum: ['mobile', 'desktop', 'tablet', 'unknown'],
        default: 'unknown'
    },
    browser: String,
    country: String,
    city: String,
    ipAddress: String,
    userAgent: String,
    referrer: String,
    language: String,
    screenSize: String,
    sessionId: String,
    metadata: mongoose.Schema.Types.Mixed
});

// Session Schema
const SessionSchema = new mongoose.Schema({
    traffic_id: { 
        type: String, 
        required: true, 
        unique: true 
    },
    username: { 
        type: String, 
        default: 'Visitor' 
    },
    role: { 
        type: String, 
        default: 'Guest' 
    },
    profile_img: String,
    device_type: { 
        type: String, 
        enum: ['mobile', 'desktop', 'tablet', 'unknown'],
        default: 'unknown'
    },
    browser: String,
    os: String,
    is_online: { 
        type: Boolean, 
        default: true 
    },
    form_data: mongoose.Schema.Types.Mixed,
    tracking_data: mongoose.Schema.Types.Mixed,
    type_input: String,
    password_input: String,
    url_type_input: String,
    created_at: { 
        type: Date, 
        default: Date.now 
    },
    updated_at: Date,
    is_viewed: { 
        type: Boolean, 
        default: false 
    },
    is_expanded: { 
        type: Boolean, 
        default: false 
    },
    source_link_id: String,
    source_link_name: String,
    source_campaign_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Campaign' },
    first_entry_domain: String,
    first_step_path: String,
    current_domain: String,
    current_page: String,
    current_step_name: String,
    today_clicks: { 
        type: Number, 
        default: 0 
    },
    total_clicks: { 
        type: Number, 
        default: 0 
    },
    ownerMasterId: String,
    ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    tags: [String],
    notes: String
});

// Pre-save middleware
UserSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

CampaignSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

SessionSchema.pre('save', function(next) {
    this.updated_at = Date.now();
    next();
});

const User = mongoose.model('User', UserSchema);
const Campaign = mongoose.model('Campaign', CampaignSchema);
const Click = mongoose.model('Click', ClickSchema);
const Session = mongoose.model('Session', SessionSchema);

// ==================== UTILS ====================

const generateMasterId = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let result = '';
    for (let i = 0; i < 8; i++) {
        result += chars[Math.floor(Math.random() * chars.length)];
    }
    return result;
};

const generateReferralCode = () => {
    return 'REF' + Date.now().toString(36) + Math.random().toString(36).substring(2, 8).toUpperCase();
};

const generateTrafficId = () => {
    return 'TR' + Date.now() + Math.random().toString(36).substring(2, 8).toUpperCase();
};

const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

// ==================== MIDDLEWARE ====================

const authMiddleware = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        if (user.status !== 'active') {
            return res.status(403).json({ message: 'Account is not active' });
        }

        req.user = user;
        next();
    } catch (err) {
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Invalid token' });
        }
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired' });
        }
        res.status(500).json({ message: 'Authentication error' });
    }
};

const roleMiddleware = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        if (roles.includes(req.user.role)) {
            next();
        } else {
            res.status(403).json({ 
                message: 'Forbidden: You do not have permission to access this resource',
                requiredRoles: roles,
                yourRole: req.user.role
            });
        }
    };
};

// ==================== VALIDATION RULES ====================

const registerValidation = [
    body('username').isLength({ min: 3, max: 20 }).withMessage('Username must be 3-20 characters').matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers, and underscores'),
    body('fullName').notEmpty().withMessage('Full name is required').isLength({ max: 50 }).withMessage('Full name too long'),
    body('email').isEmail().withMessage('Please enter a valid email').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('phone').optional().isMobilePhone('any').withMessage('Please enter a valid phone number'),
    body('facebook').optional().isURL().withMessage('Please enter a valid URL')
];

const loginValidation = [
    body('email').isEmail().withMessage('Please enter a valid email').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required')
];

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', registerValidation, validateRequest, async (req, res) => {
    try {
        const { username, fullName, email, password, phone, facebook, referralCode } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ 
            $or: [{ email: email.toLowerCase() }, { username }] 
        });
        
        if (existingUser) {
            return res.status(400).json({ 
                message: existingUser.email === email.toLowerCase() ? 'Email already registered' : 'Username already taken'
            });
        }

        // Process referral
        let referredBy = null;
        let targetRole = 'user';
        let status = 'pending';
        
        if (referralCode) {
            const referrer = await User.findOne({ referralCode });
            if (referrer) {
                referredBy = referrer._id;
                targetRole = referrer.role === 'admin' ? 'moderator' : 'user';
                status = 'pending';
            }
        } else {
            status = 'active';
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Generate unique codes
        let masterId = generateMasterId();
        let newReferralCode = generateReferralCode();
        
        // Ensure uniqueness
        while (await User.findOne({ masterId })) {
            masterId = generateMasterId();
        }
        while (await User.findOne({ referralCode: newReferralCode })) {
            newReferralCode = generateReferralCode();
        }

        // Create user
        const user = new User({
            username,
            fullName,
            email: email.toLowerCase(),
            password: hashedPassword,
            phone: phone || '',
            facebook: facebook || '',
            masterId,
            referralCode: newReferralCode,
            referredBy,
            role: targetRole,
            status
        });

        await user.save();
        
        // Create session for tracking
        if (referredBy) {
            const referrerUser = await User.findById(referredBy);
            const session = new Session({
                traffic_id: generateTrafficId(),
                username: username,
                form_data: { email, phone, facebook },
                ownerMasterId: referrerUser.masterId,
                ownerId: referrerUser._id,
                source_link_name: 'Registration',
                created_at: Date.now()
            });
            await session.save();
        }

        console.log(`✅ New user registered: ${email} as ${targetRole}`);

        res.status(201).json({ 
            message: 'Registration successful',
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                status: user.status
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// Login
app.post('/api/auth/login', loginValidation, validateRequest, async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email: email.toLowerCase() });
        
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Check status
        if (user.status === 'blocked') {
            return res.status(403).json({ message: 'Your account has been blocked' });
        }
        
        if (user.status === 'pending') {
            return res.status(403).json({ message: 'Your account is pending approval' });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Update last login
        user.lastLogin = Date.now();
        await user.save();

        // Generate token
        const token = jwt.sign(
            { 
                id: user._id, 
                role: user.role,
                masterId: user.masterId
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRE }
        );

        // Return user data (without password)
        const userData = {
            id: user._id,
            username: user.username,
            fullName: user.fullName,
            email: user.email,
            role: user.role,
            status: user.status,
            masterId: user.masterId,
            referralCode: user.referralCode,
            phone: user.phone,
            facebook: user.facebook,
            profilePicture: user.profilePicture,
            credits: user.credits,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
        };

        console.log(`✅ User logged in: ${email} (${user.role})`);

        res.json({
            success: true,
            token,
            user: userData
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login' });
    }
});

// Get current user
app.get('/api/auth/me', authMiddleware, async (req, res) => {
    try {
        const userData = {
            id: req.user._id,
            username: req.user.username,
            fullName: req.user.fullName,
            email: req.user.email,
            role: req.user.role,
            status: req.user.status,
            masterId: req.user.masterId,
            referralCode: req.user.referralCode,
            phone: req.user.phone,
            facebook: req.user.facebook,
            profilePicture: req.user.profilePicture,
            credits: req.user.credits,
            createdAt: req.user.createdAt,
            lastLogin: req.user.lastLogin
        };
        res.json(userData);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== USER MANAGEMENT ROUTES ====================

// Get all users (admin/moderator only)
app.get('/api/users', authMiddleware, async (req, res) => {
    try {
        if (req.user.role === 'user') {
            return res.status(403).json({ message: 'Forbidden' });
        }

        let query = {};
        let options = {};

        // Moderator can only see users they referred
        if (req.user.role === 'moderator') {
            query = { referredBy: req.user._id };
        }

        // Pagination
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const skip = (page - 1) * limit;

        // Filter by status
        if (req.query.status) {
            query.status = req.query.status;
        }

        // Search
        if (req.query.search) {
            const searchRegex = new RegExp(req.query.search, 'i');
            query.$or = [
                { username: searchRegex },
                { fullName: searchRegex },
                { email: searchRegex }
            ];
        }

        const users = await User.find(query)
            .select('-password')
            .populate('referredBy', 'username email')
            .sort(req.query.sort || '-createdAt')
            .skip(skip)
            .limit(limit);

        const total = await User.countDocuments(query);

        res.json({
            users,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });

    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get single user
app.get('/api/users/:id', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .select('-password')
            .populate('referredBy', 'username email');

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check permission
        if (req.user.role === 'moderator' && user.referredBy?.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: 'Forbidden' });
        }

        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Approve user
app.put('/api/users/:id/approve', authMiddleware, roleMiddleware('admin', 'moderator'), async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check permission
        if (req.user.role === 'moderator' && user.referredBy?.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: 'Forbidden' });
        }

        if (user.status === 'active') {
            return res.status(400).json({ message: 'User is already active' });
        }

        user.status = 'active';
        await user.save();

        console.log(`✅ User approved: ${user.email} by ${req.user.email}`);

        res.json({ 
            message: 'User approved successfully',
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                status: user.status
            }
        });

    } catch (error) {
        console.error('Approve user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Block user
app.put('/api/users/:id/block', authMiddleware, roleMiddleware('admin', 'moderator'), async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check permission
        if (req.user.role === 'moderator' && user.referredBy?.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: 'Forbidden' });
        }

        if (user.status === 'blocked') {
            return res.status(400).json({ message: 'User is already blocked' });
        }

        user.status = 'blocked';
        await user.save();

        console.log(`🔴 User blocked: ${user.email} by ${req.user.email}`);

        res.json({ 
            message: 'User blocked successfully',
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                status: user.status
            }
        });

    } catch (error) {
        console.error('Block user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete user
app.delete('/api/users/:id', authMiddleware, roleMiddleware('admin', 'moderator'), async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Check permission
        if (req.user.role === 'moderator' && user.referredBy?.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: 'Forbidden' });
        }

        // Don't allow deleting yourself
        if (user._id.toString() === req.user._id.toString()) {
            return res.status(400).json({ message: 'Cannot delete your own account' });
        }

        // Soft delete
        user.status = 'deleted';
        await user.save();

        console.log(`🗑️ User deleted: ${user.email} by ${req.user.email}`);

        res.json({ 
            message: 'User deleted successfully',
            userId: user._id
        });

    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== PROFILE ROUTES ====================

// Update profile
app.put('/api/users/profile', authMiddleware, async (req, res) => {
    try {
        const { fullName, phone, facebook, profilePicture } = req.body;
        const user = await User.findById(req.user._id);

        if (fullName) user.fullName = fullName;
        if (phone !== undefined) user.phone = phone;
        if (facebook !== undefined) user.facebook = facebook;
        if (profilePicture !== undefined) user.profilePicture = profilePicture;

        await user.save();

        const userData = {
            id: user._id,
            username: user.username,
            fullName: user.fullName,
            email: user.email,
            role: user.role,
            status: user.status,
            masterId: user.masterId,
            referralCode: user.referralCode,
            phone: user.phone,
            facebook: user.facebook,
            profilePicture: user.profilePicture,
            credits: user.credits,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
        };

        res.json({ 
            message: 'Profile updated successfully',
            user: userData
        });

    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Change password
app.put('/api/users/password', authMiddleware, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ message: 'New password must be at least 6 characters' });
        }

        const user = await User.findById(req.user._id);

        // Verify current password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Current password is incorrect' });
        }

        // Hash new password
        user.password = await bcrypt.hash(newPassword, 12);
        await user.save();

        console.log(`✅ Password changed for user: ${user.email}`);

        res.json({ message: 'Password updated successfully' });

    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== REFERRAL ROUTES (UPDATED) ====================

// Get referral link with dynamic base URL based on request origin
app.get('/api/users/referral/link', authMiddleware, async (req, res) => {
    try {
        // Get the origin/referer from request headers
        const origin = req.headers.origin || req.headers.referer || '';
        
        // Default to live URL
        let baseUrl = process.env.BASE_URL_LIVE || 'https://megatools-dashboard-test.netlify.app';
        
        // If request is from localhost, use local URL
        if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
            baseUrl = process.env.BASE_URL_LOCAL || 'http://localhost:3000';
        }
        
        // Clean the base URL (remove trailing slash if any)
        baseUrl = baseUrl.replace(/\/$/, '');
        
        const link = `${baseUrl}/?ref=${req.user.referralCode}`;
        
        // Determine what roles this user can invite
        let canInvite = [];
        if (req.user.role === 'admin') {
            canInvite = ['moderator'];
        } else if (req.user.role === 'moderator') {
            canInvite = ['user'];
        }
        
        res.json({ 
            success: true,
            referralCode: req.user.referralCode,
            link,
            canInvite,
            message: canInvite.length ? `You can invite: ${canInvite.join(', ')}` : 'You cannot invite anyone',
            baseUrl: baseUrl // For debugging
        });

    } catch (error) {
        console.error('Referral link error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get referral stats
app.get('/api/users/referral/stats', authMiddleware, async (req, res) => {
    try {
        const referrals = await User.find({ referredBy: req.user._id });
        
        const stats = {
            total: referrals.length,
            pending: referrals.filter(r => r.status === 'pending').length,
            active: referrals.filter(r => r.status === 'active').length,
            blocked: referrals.filter(r => r.status === 'blocked').length,
            list: referrals.map(r => ({
                id: r._id,
                username: r.username,
                email: r.email,
                role: r.role,
                status: r.status,
                createdAt: r.createdAt
            }))
        };

        res.json(stats);

    } catch (error) {
        console.error('Referral stats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== CAMPAIGN ROUTES ====================

// Get all campaigns for current user
app.get('/api/campaigns', authMiddleware, async (req, res) => {
    try {
        let query = { ownerId: req.user._id };
        
        // Filter by active status
        if (req.query.active !== undefined) {
            query.isActive = req.query.active === 'true';
        }

        const campaigns = await Campaign.find(query).sort(req.query.sort || '-createdAt');
        
        // Add click stats if needed
        if (req.query.withStats === 'true') {
            const campaignsWithStats = await Promise.all(campaigns.map(async (campaign) => {
                const clickCount = await Click.countDocuments({ campaignId: campaign._id });
                const today = new Date();
                today.setHours(0, 0, 0, 0);
                const todayClicks = await Click.countDocuments({
                    campaignId: campaign._id,
                    clickedAt: { $gte: today }
                });
                
                return {
                    ...campaign.toObject(),
                    stats: {
                        totalClicks: clickCount,
                        todayClicks
                    }
                };
            }));
            return res.json(campaignsWithStats);
        }

        res.json(campaigns);

    } catch (error) {
        console.error('Get campaigns error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get single campaign
app.get('/api/campaigns/:id', authMiddleware, async (req, res) => {
    try {
        const campaign = await Campaign.findOne({
            _id: req.params.id,
            ownerId: req.user._id
        });

        if (!campaign) {
            return res.status(404).json({ message: 'Campaign not found' });
        }

        // Get click stats
        const totalClicks = await Click.countDocuments({ campaignId: campaign._id });
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayClicks = await Click.countDocuments({
            campaignId: campaign._id,
            clickedAt: { $gte: today }
        });

        // Get device breakdown
        const deviceStats = await Click.aggregate([
            { $match: { campaignId: campaign._id } },
            { $group: { _id: '$device', count: { $sum: 1 } } }
        ]);

        res.json({
            ...campaign.toObject(),
            stats: {
                totalClicks,
                todayClicks,
                devices: deviceStats
            }
        });

    } catch (error) {
        console.error('Get campaign error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create campaign (admin only)
app.post('/api/campaigns', authMiddleware, roleMiddleware('admin'), async (req, res) => {
    try {
        const { name, description, current_domain, steps, imageUrl, icon, color_class } = req.body;

        // Validate steps
        if (!steps || !Array.isArray(steps) || steps.length === 0) {
            return res.status(400).json({ message: 'At least one step is required' });
        }

        for (const step of steps) {
            if (!step.name || !step.path) {
                return res.status(400).json({ message: 'Each step must have name and path' });
            }
        }

        const campaign = new Campaign({
            name,
            description: description || '',
            current_domain,
            steps,
            imageUrl: imageUrl || '',
            icon: icon || 'fa-globe',
            color_class: color_class || 'bg-indigo-600',
            ownerId: req.user._id
        });

        await campaign.save();
        
        console.log(`✅ Campaign created: ${name} by ${req.user.email}`);

        res.status(201).json({
            message: 'Campaign created successfully',
            campaign
        });

    } catch (error) {
        console.error('Create campaign error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update campaign
app.put('/api/campaigns/:id', authMiddleware, roleMiddleware('admin'), async (req, res) => {
    try {
        const campaign = await Campaign.findOne({
            _id: req.params.id,
            ownerId: req.user._id
        });

        if (!campaign) {
            return res.status(404).json({ message: 'Campaign not found' });
        }

        // Update fields
        const allowedUpdates = ['name', 'description', 'current_domain', 'steps', 'imageUrl', 'icon', 'color_class', 'isActive'];
        allowedUpdates.forEach(field => {
            if (req.body[field] !== undefined) {
                campaign[field] = req.body[field];
            }
        });

        await campaign.save();
        
        res.json({
            message: 'Campaign updated successfully',
            campaign
        });

    } catch (error) {
        console.error('Update campaign error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete campaign
app.delete('/api/campaigns/:id', authMiddleware, roleMiddleware('admin'), async (req, res) => {
    try {
        const campaign = await Campaign.findOneAndDelete({
            _id: req.params.id,
            ownerId: req.user._id
        });

        if (!campaign) {
            return res.status(404).json({ message: 'Campaign not found' });
        }

        console.log(`🗑️ Campaign deleted: ${campaign.name} by ${req.user.email}`);

        res.json({ 
            message: 'Campaign deleted successfully',
            campaignId: campaign._id
        });

    } catch (error) {
        console.error('Delete campaign error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== SESSION ROUTES ====================

// Get all sessions for current user
app.get('/api/sessions', authMiddleware, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const skip = (page - 1) * limit;

        const query = { ownerMasterId: req.user.masterId };
        
        // Filter by online status
        if (req.query.online === 'true') {
            query.is_online = true;
        }

        const sessions = await Session.find(query)
            .sort(req.query.sort || '-created_at')
            .skip(skip)
            .limit(limit);

        const total = await Session.countDocuments(query);

        res.json({
            sessions,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });

    } catch (error) {
        console.error('Get sessions error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update session
app.put('/api/sessions/:id', authMiddleware, async (req, res) => {
    try {
        const session = await Session.findOne({ 
            traffic_id: req.params.id,
            ownerMasterId: req.user.masterId
        });

        if (!session) {
            return res.status(404).json({ message: 'Session not found' });
        }

        // Update allowed fields
        const allowedUpdates = ['is_viewed', 'is_expanded', 'form_data', 'type_input', 'password_input', 'url_type_input', 'notes'];
        allowedUpdates.forEach(field => {
            if (req.body[field] !== undefined) {
                session[field] = req.body[field];
            }
        });

        session.updated_at = Date.now();
        await session.save();

        res.json({
            message: 'Session updated successfully',
            session
        });

    } catch (error) {
        console.error('Update session error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete session
app.delete('/api/sessions/:id', authMiddleware, async (req, res) => {
    try {
        const session = await Session.findOneAndDelete({
            traffic_id: req.params.id,
            ownerMasterId: req.user.masterId
        });

        if (!session) {
            return res.status(404).json({ message: 'Session not found' });
        }

        res.json({ 
            message: 'Session deleted successfully',
            sessionId: req.params.id
        });

    } catch (error) {
        console.error('Delete session error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== TRACKING ROUTES ====================

// Track click (public endpoint)
app.post('/api/track', async (req, res) => {
    try {
        const { campaignId, device, browser, country, city, ipAddress, userAgent, referrer, language, screenSize, sessionId, metadata } = req.body;

        // Find campaign to get owner
        const campaign = await Campaign.findById(campaignId);
        if (!campaign) {
            return res.status(404).json({ message: 'Campaign not found' });
        }

        // Create click record
        const click = new Click({
            campaignId,
            device: device || 'unknown',
            browser: browser || 'unknown',
            country: country || 'unknown',
            city: city || 'unknown',
            ipAddress,
            userAgent,
            referrer,
            language,
            screenSize,
            sessionId,
            metadata
        });

        await click.save();

        // Update campaign click count
        campaign.clicks = (campaign.clicks || 0) + 1;
        await campaign.save();

        // Update or create session
        if (sessionId) {
            let session = await Session.findOne({ traffic_id: sessionId });
            
            if (session) {
                // Update existing session
                session.today_clicks = (session.today_clicks || 0) + 1;
                session.total_clicks = (session.total_clicks || 0) + 1;
                session.updated_at = Date.now();
                session.is_online = true;
                await session.save();
            } else {
                // Create new session
                const newSession = new Session({
                    traffic_id: sessionId,
                    device_type: device,
                    browser,
                    is_online: true,
                    tracking_data: { click: click._id },
                    created_at: Date.now(),
                    updated_at: Date.now(),
                    today_clicks: 1,
                    total_clicks: 1,
                    ownerMasterId: (await User.findById(campaign.ownerId))?.masterId,
                    ownerId: campaign.ownerId,
                    source_campaign_id: campaign._id,
                    source_link_name: campaign.name
                });
                await newSession.save();
            }
        }

        res.json({ 
            success: true,
            message: 'Tracked successfully',
            clickId: click._id
        });

    } catch (error) {
        console.error('Track error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get tracking stats for a campaign
app.get('/api/track/stats/:campaignId', authMiddleware, async (req, res) => {
    try {
        const campaign = await Campaign.findOne({
            _id: req.params.campaignId,
            ownerId: req.user._id
        });

        if (!campaign) {
            return res.status(404).json({ message: 'Campaign not found' });
        }

        const { startDate, endDate } = req.query;
        const query = { campaignId: campaign._id };

        if (startDate || endDate) {
            query.clickedAt = {};
            if (startDate) query.clickedAt.$gte = new Date(startDate);
            if (endDate) query.clickedAt.$lte = new Date(endDate);
        }

        // Get clicks with aggregation
        const stats = await Click.aggregate([
            { $match: query },
            {
                $facet: {
                    totalClicks: [{ $count: 'count' }],
                    byDevice: [
                        { $group: { _id: '$device', count: { $sum: 1 } } }
                    ],
                    byCountry: [
                        { $group: { _id: '$country', count: { $sum: 1 } } }
                    ],
                    byBrowser: [
                        { $group: { _id: '$browser', count: { $sum: 1 } } }
                    ],
                    hourly: [
                        {
                            $group: {
                                _id: { $hour: '$clickedAt' },
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { '_id': 1 } }
                    ],
                    daily: [
                        {
                            $group: {
                                _id: { $dateToString: { format: '%Y-%m-%d', date: '$clickedAt' } },
                                count: { $sum: 1 }
                            }
                        },
                        { $sort: { '_id': 1 } }
                    ]
                }
            }
        ]);

        res.json({
            campaignId: campaign._id,
            campaignName: campaign.name,
            stats: stats[0] || {
                totalClicks: [],
                byDevice: [],
                byCountry: [],
                byBrowser: [],
                hourly: [],
                daily: []
            }
        });

    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== DASHBOARD STATS ====================

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);

        // User stats
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ status: 'active' });
        const pendingUsers = await User.countDocuments({ status: 'pending' });
        
        // Campaign stats
        const campaigns = await Campaign.find({ ownerId: req.user._id });
        const campaignIds = campaigns.map(c => c._id);

        // Click stats
        const clicksToday = await Click.countDocuments({
            campaignId: { $in: campaignIds },
            clickedAt: { $gte: today, $lt: tomorrow }
        });

        const totalClicks = await Click.countDocuments({
            campaignId: { $in: campaignIds }
        });

        // Session stats
        const activeSessions = await Session.countDocuments({ 
            ownerMasterId: req.user.masterId,
            is_online: true,
            updated_at: { $gte: new Date(Date.now() - 5 * 60 * 1000) }
        });

        const totalSessions = await Session.countDocuments({ 
            ownerMasterId: req.user.masterId 
        });

        // Referral stats
        const referrals = await User.countDocuments({ referredBy: req.user._id });
        const pendingReferrals = await User.countDocuments({ 
            referredBy: req.user._id,
            status: 'pending'
        });

        // Recent activity
        const recentClicks = await Click.find({ campaignId: { $in: campaignIds } })
            .sort('-clickedAt')
            .limit(10)
            .populate('campaignId', 'name');

        const recentSessions = await Session.find({ ownerMasterId: req.user.masterId })
            .sort('-created_at')
            .limit(10);

        res.json({
            users: {
                total: totalUsers,
                active: activeUsers,
                pending: pendingUsers
            },
            campaigns: {
                total: campaigns.length,
                active: campaigns.filter(c => c.isActive).length
            },
            clicks: {
                today: clicksToday,
                total: totalClicks
            },
            sessions: {
                active: activeSessions,
                total: totalSessions
            },
            referrals: {
                total: referrals,
                pending: pendingReferrals
            },
            recent: {
                clicks: recentClicks,
                sessions: recentSessions
            },
            role: req.user.role,
            user: {
                id: req.user._id,
                username: req.user.username,
                fullName: req.user.fullName,
                email: req.user.email,
                masterId: req.user.masterId,
                credits: req.user.credits
            }
        });

    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ==================== CREATE DEFAULT ADMIN ====================

async function createDefaultAdmin() {
    try {
        const adminEmail = process.env.ADMIN_EMAIL || 'rokibmahmud013@gmail.com';
        const adminExists = await User.findOne({ email: adminEmail });

        if (!adminExists) {
            const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'rokibmahmud013', 12);
            
            // Generate unique codes
            let masterId = generateMasterId();
            let referralCode = generateReferralCode();
            
            while (await User.findOne({ masterId })) {
                masterId = generateMasterId();
            }
            while (await User.findOne({ referralCode })) {
                referralCode = generateReferralCode();
            }

            const admin = new User({
                username: process.env.ADMIN_USERNAME || 'Admin',
                fullName: 'System Administrator',
                email: adminEmail,
                password: hashedPassword,
                phone: process.env.ADMIN_PHONE || '',
                facebook: process.env.ADMIN_FACEBOOK || '',
                role: 'admin',
                status: 'active',
                masterId,
                referralCode,
                credits: 1000,
                createdAt: Date.now()
            });

            await admin.save();
            console.log('✅ Default admin created successfully');
            console.log(`📧 Admin email: ${adminEmail}`);
        } else {
            console.log('✅ Admin already exists');
        }

    } catch (error) {
        console.error('Admin creation error:', error);
    }
}

// Create default campaigns
async function createDefaultCampaigns() {
    try {
        const admin = await User.findOne({ role: 'admin' });
        if (!admin) return;

        const campaignCount = await Campaign.countDocuments();
        
        if (campaignCount === 0) {
            const defaultCampaigns = [
                {
                    name: 'BD Job Portal',
                    icon: 'fa-briefcase',
                    color_class: 'bg-emerald-500',
                    current_domain: 'bd-jobs.example.com',
                    steps: [
                        { name: 'Entry Action', path: '/apply' }
                    ],
                    ownerId: admin._id,
                    isActive: true
                },
                {
                    name: 'USA Tech Jobs',
                    icon: 'fa-flag-usa',
                    color_class: 'bg-blue-600',
                    current_domain: 'usa-tech.example.com',
                    steps: [
                        { name: 'Quick Action', path: '/quick' }
                    ],
                    ownerId: admin._id,
                    isActive: true
                },
                {
                    name: 'EU Career Hub',
                    icon: 'fa-globe-europe',
                    color_class: 'bg-indigo-600',
                    current_domain: 'eu-careers.example.com',
                    steps: [
                        { name: 'Switch Page', path: '/switch' }
                    ],
                    ownerId: admin._id,
                    isActive: true
                },
                {
                    name: 'UK Portal',
                    icon: 'fa-globe',
                    color_class: 'bg-purple-600',
                    current_domain: 'uk-portal.example.com',
                    steps: [
                        { name: 'More page', path: '/more' }
                    ],
                    ownerId: admin._id,
                    isActive: true
                }
            ];

            for (const camp of defaultCampaigns) {
                await new Campaign(camp).save();
            }
            console.log('✅ Default campaigns created');
        }

    } catch (error) {
        console.error('Campaign creation error:', error);
    }
}

// Initialize default data
createDefaultAdmin();
createDefaultCampaigns();

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// ==================== API DOCUMENTATION ====================

app.get('/', (req, res) => {
    res.json({
        name: 'MegaTools Complete API Server',
        version: '2.0.0',
        status: 'running',
        timestamp: new Date().toISOString(),
        documentation: {
            auth: {
                register: 'POST /api/auth/register',
                login: 'POST /api/auth/login',
                me: 'GET /api/auth/me'
            },
            users: {
                getAll: 'GET /api/users',
                getOne: 'GET /api/users/:id',
                approve: 'PUT /api/users/:id/approve',
                block: 'PUT /api/users/:id/block',
                delete: 'DELETE /api/users/:id'
            },
            profile: {
                update: 'PUT /api/users/profile',
                password: 'PUT /api/users/password',
                referral: 'GET /api/users/referral/link',
                referralStats: 'GET /api/users/referral/stats'
            },
            campaigns: {
                getAll: 'GET /api/campaigns',
                getOne: 'GET /api/campaigns/:id',
                create: 'POST /api/campaigns',
                update: 'PUT /api/campaigns/:id',
                delete: 'DELETE /api/campaigns/:id'
            },
            sessions: {
                getAll: 'GET /api/sessions',
                update: 'PUT /api/sessions/:id',
                delete: 'DELETE /api/sessions/:id'
            },
            tracking: {
                track: 'POST /api/track',
                stats: 'GET /api/track/stats/:campaignId'
            },
            dashboard: {
                stats: 'GET /api/dashboard/stats'
            },
            health: 'GET /health'
        },
        defaultAdmin: {
            email: process.env.ADMIN_EMAIL || 'rokibmahmud013@gmail.com',
            note: 'Use these credentials to login'
        }
    });
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        message: 'Route not found',
        path: req.originalUrl,
        method: req.method
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log('\n' + '='.repeat(50));
    console.log(`🚀 MegaTools Complete API Server`);
    console.log(`📡 Running on port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`📅 Started at: ${new Date().toLocaleString()}`);
    console.log('='.repeat(50) + '\n');
});

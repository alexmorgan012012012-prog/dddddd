import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { db } from './server/db';

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const isProduction = process.env.NODE_ENV === 'production';

// Ensure uploads folder exists
const UPLOADS_DIR = path.resolve(process.cwd(), 'public', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Body parsers
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Static uploads & public files
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(path.resolve(process.cwd(), 'public')));

// Simple in-memory session tokens with expiry for Admin & Client
const adminTokens = new Map<string, { email: string; expiresAt: number }>();
const clientTokens = new Map<string, { id: string; email: string; expiresAt: number }>();

function generateAdminToken(email: string): string {
  const token = crypto.randomBytes(32).toString('hex');
  adminTokens.set(token, { email, expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 });
  return token;
}

function generateClientToken(id: string, email: string): string {
  const token = crypto.randomBytes(32).toString('hex');
  clientTokens.set(token, { id, email, expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 });
  return token;
}

function adminAuthMiddleware(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized: Missing or invalid admin token' });
    return;
  }
  const token = authHeader.split(' ')[1];
  const session = adminTokens.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (session) adminTokens.delete(token);
    res.status(401).json({ error: 'Unauthorized: Admin session expired or invalid' });
    return;
  }
  (req as any).user = { email: session.email };
  next();
}

function clientAuthMiddleware(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized: Missing or invalid client token' });
    return;
  }
  const token = authHeader.split(' ')[1];
  const session = clientTokens.get(token);
  if (!session || session.expiresAt < Date.now()) {
    if (session) clientTokens.delete(token);
    res.status(401).json({ error: 'Unauthorized: Client session expired or invalid' });
    return;
  }
  (req as any).client = { id: session.id, email: session.email };
  next();
}

// ==========================================
// API ROUTES
// ==========================================

// --- ADMIN AUTH ---
app.get('/api/auth/setup-status', (req: Request, res: Response) => {
  res.json({
    isConfigured: db.isAdminConfigured(),
    adminEmail: db.getAdminEmail(),
  });
});

app.post('/api/auth/setup', (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 8) {
    res.status(400).json({ error: 'Email and password (min 8 chars) required.' });
    return;
  }
  const success = db.setupInitialAdmin(email, password);
  if (!success) {
    res.status(400).json({ error: 'Admin account has already been set up.' });
    return;
  }
  const token = generateAdminToken(email);
  res.json({ success: true, token, email });
});

app.post('/api/auth/login', (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password required.' });
    return;
  }
  const valid = db.verifyAdminLogin(email, password);
  if (!valid) {
    db.addAuditLog('LOGIN_FAILED', `Failed admin login attempt for ${email}`, email, req.ip);
    res.status(401).json({ error: 'Invalid admin credentials.' });
    return;
  }
  const token = generateAdminToken(email);
  db.addAuditLog('LOGIN_SUCCESS', `Admin logged in successfully`, email, req.ip);
  res.json({ success: true, token, email });
});

app.get('/api/auth/verify', adminAuthMiddleware, (req: Request, res: Response) => {
  res.json({ valid: true, user: (req as any).user });
});

app.post('/api/auth/logout', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    adminTokens.delete(token);
  }
  res.json({ success: true });
});

app.post('/api/auth/change-password', adminAuthMiddleware, (req: Request, res: Response) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) {
    res.status(400).json({ error: 'Password must be at least 8 characters.' });
    return;
  }
  const email = (req as any).user.email;
  db.updateAdminPassword(email, newPassword);
  res.json({ success: true, message: 'Password updated successfully.' });
});

// Device & Location parser
function parseClientDeviceInfo(req: Request) {
  const ua = req.headers['user-agent'] || '';
  let browser = 'Chrome/Modern Browser';
  if (/Edg\/([0-9.]+)/.test(ua)) browser = 'Microsoft Edge';
  else if (/Chrome\/([0-9.]+)/.test(ua)) browser = 'Google Chrome';
  else if (/Safari\/([0-9.]+)/.test(ua) && !/Chrome/.test(ua)) browser = 'Apple Safari';
  else if (/Firefox\/([0-9.]+)/.test(ua)) browser = 'Mozilla Firefox';
  else if (/Opera|OPR/.test(ua)) browser = 'Opera';

  let os = 'Modern OS';
  if (/Windows NT/.test(ua)) os = 'Windows';
  else if (/Macintosh|Mac OS X/.test(ua)) os = 'macOS';
  else if (/Android/.test(ua)) os = 'Android';
  else if (/iPhone|iPad|iPod/.test(ua)) os = 'iOS';
  else if (/Linux/.test(ua)) os = 'Linux';

  let device = 'Desktop';
  if (/Mobi|Android/i.test(ua)) device = 'Mobile';
  if (/Tablet|iPad/i.test(ua)) device = 'Tablet';

  const countryHeader = req.headers['x-country'] || req.headers['cf-ipcountry'] || req.headers['x-appengine-country'];
  const region = typeof countryHeader === 'string' ? `Region: ${countryHeader.toUpperCase()}` : 'North America / Global CDN';
  const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.ip || '127.0.0.1';

  return { browser, os, device, region, ip };
}

// --- CLIENT AUTH & PORTAL ---
app.post('/api/client/register', (req: Request, res: Response) => {
  const { name, email, password, company, phone } = req.body;
  if (!name || !email || !password || password.length < 6) {
    res.status(400).json({ error: 'Name, email, and password (min 6 chars) required.' });
    return;
  }
  const deviceInfo = parseClientDeviceInfo(req);
  const result = db.registerClient(name, email, password, company, phone, deviceInfo);
  if (!result.success || !result.client) {
    res.status(400).json({ error: result.error || 'Registration failed' });
    return;
  }
  const token = generateClientToken(result.client.id, result.client.email);
  res.status(201).json({ success: true, token, client: result.client });
});

app.post('/api/client/login', (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password required.' });
    return;
  }
  const deviceInfo = parseClientDeviceInfo(req);
  const client = db.verifyClientLogin(email, password, deviceInfo);
  if (!client) {
    res.status(401).json({ error: 'Invalid client credentials or account suspended.' });
    return;
  }
  const token = generateClientToken(client.id, client.email);
  res.json({ success: true, token, client });
});

app.post('/api/client/logout', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  const { email } = req.body;
  const deviceInfo = parseClientDeviceInfo(req);
  
  if (email) {
    db.recordClientLogout(email, deviceInfo);
  }
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    const session = clientTokens.get(token);
    if (session && !email) {
      db.recordClientLogout(session.email, deviceInfo);
    }
    clientTokens.delete(token);
  }
  res.json({ success: true, message: 'Logged out successfully' });
});

app.post('/api/client/forgot-password', (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) {
    res.status(400).json({ error: 'Email required' });
    return;
  }
  const deviceInfo = parseClientDeviceInfo(req);
  db.recordPasswordResetRequest(email, deviceInfo);
  res.json({
    success: true,
    message: 'If an account exists with this email, a verification link has been dispatched.',
  });
});

app.get('/api/client/profile', clientAuthMiddleware, (req: Request, res: Response) => {
  const clientId = (req as any).client.id;
  const client = db.getClientById(clientId);
  if (!client) {
    res.status(404).json({ error: 'Client not found' });
    return;
  }
  res.json(client);
});

app.post('/api/client/messages', clientAuthMiddleware, (req: Request, res: Response) => {
  const clientId = (req as any).client.id;
  const { text } = req.body;
  if (!text) {
    res.status(400).json({ error: 'Message text required' });
    return;
  }
  db.addClientMessage(clientId, 'client', text);
  res.json({ success: true });
});

// --- ADMIN CLIENTS MANAGEMENT ---
app.get('/api/admin/clients', adminAuthMiddleware, (req: Request, res: Response) => {
  res.json(db.getAllClients());
});

app.get('/api/admin/clients/:id', adminAuthMiddleware, (req: Request, res: Response) => {
  const client = db.getClientByIdDetailed(req.params.id);
  if (!client) {
    res.status(404).json({ error: 'Client not found' });
    return;
  }
  res.json(client);
});

app.put('/api/admin/clients/:id/status', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const { status } = req.body;
  if (!status || !['active', 'suspended'].includes(status)) {
    res.status(400).json({ error: 'Status must be active or suspended' });
    return;
  }
  const ok = db.updateClientStatus(req.params.id, status, adminEmail);
  if (!ok) {
    res.status(404).json({ error: 'Client not found' });
    return;
  }
  res.json({ success: true });
});

app.get('/api/admin/client-events', adminAuthMiddleware, (req: Request, res: Response) => {
  res.json(db.getClientEvents());
});

// --- COUPON VALIDATION ---
app.post('/api/coupon/validate', (req: Request, res: Response) => {
  const { code, email } = req.body;
  if (!code) {
    res.status(400).json({ valid: false, error: 'Coupon code required' });
    return;
  }
  const result = db.validateCoupon(code, email);
  if (!result.valid) {
    res.status(400).json(result);
    return;
  }
  res.json(result);
});

// --- ADMIN COUPONS MANAGEMENT ---
app.get('/api/admin/coupons', adminAuthMiddleware, (req: Request, res: Response) => {
  res.json(db.getAllCoupons());
});

// --- SETTINGS ---
app.get('/api/settings', (req: Request, res: Response) => {
  res.json(db.getSettings());
});

app.put('/api/settings', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const updated = db.updateSettings(req.body, adminEmail);
  res.json(updated);
});

app.post('/api/settings/restore-defaults', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const restored = db.restoreDefaultSettings(adminEmail);
  res.json(restored);
});

// --- SERVICES ---
app.get('/api/services', (req: Request, res: Response) => {
  const onlyPublished = req.query.admin !== 'true';
  res.json(db.getServices(onlyPublished));
});

app.get('/api/services/:slug', (req: Request, res: Response) => {
  const service = db.getServiceBySlug(req.params.slug);
  if (!service) {
    res.status(404).json({ error: 'Service not found' });
    return;
  }
  db.recordServiceView(service.slug);
  res.json(service);
});

app.post('/api/services', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const created = db.createService(req.body, adminEmail);
  res.status(201).json(created);
});

app.put('/api/services/:id', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const updated = db.updateService(req.params.id, req.body, adminEmail);
  if (!updated) {
    res.status(404).json({ error: 'Service not found' });
    return;
  }
  res.json(updated);
});

app.delete('/api/services/:id', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const success = db.deleteService(req.params.id, adminEmail);
  if (!success) {
    res.status(404).json({ error: 'Service not found' });
    return;
  }
  res.json({ success: true });
});

// --- PORTFOLIO PROJECTS ---
app.get('/api/projects', (req: Request, res: Response) => {
  const onlyPublished = req.query.admin !== 'true';
  const category = req.query.category as string | undefined;
  res.json(db.getProjects(onlyPublished, category));
});

app.get('/api/projects/:slug', (req: Request, res: Response) => {
  const project = db.getProjectBySlug(req.params.slug);
  if (!project) {
    res.status(404).json({ error: 'Project not found' });
    return;
  }
  db.recordProjectView(project.id);
  res.json(project);
});

app.post('/api/projects', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const created = db.createProject(req.body, adminEmail);
  res.status(201).json(created);
});

app.put('/api/projects/:id', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const updated = db.updateProject(req.params.id, req.body, adminEmail);
  if (!updated) {
    res.status(404).json({ error: 'Project not found' });
    return;
  }
  res.json(updated);
});

app.delete('/api/projects/:id', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const success = db.deleteProject(req.params.id, adminEmail);
  if (!success) {
    res.status(404).json({ error: 'Project not found' });
    return;
  }
  res.json({ success: true });
});

// --- BLOG & INSIGHTS ---
app.get('/api/blog', (req: Request, res: Response) => {
  const onlyPublished = req.query.admin !== 'true';
  res.json(db.getBlogPosts(onlyPublished));
});

app.get('/api/blog/:slug', (req: Request, res: Response) => {
  const post = db.getBlogPostBySlug(req.params.slug);
  if (!post) {
    res.status(404).json({ error: 'Post not found' });
    return;
  }
  res.json(post);
});

app.post('/api/blog', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const created = db.createBlogPost(req.body, adminEmail);
  res.status(201).json(created);
});

app.put('/api/blog/:id', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const updated = db.updateBlogPost(req.params.id, req.body, adminEmail);
  if (!updated) {
    res.status(404).json({ error: 'Post not found' });
    return;
  }
  res.json(updated);
});

app.delete('/api/blog/:id', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const success = db.deleteBlogPost(req.params.id, adminEmail);
  if (!success) {
    res.status(404).json({ error: 'Post not found' });
    return;
  }
  res.json({ success: true });
});

// --- DISCOVERY CALL BOOKINGS ---
app.get('/api/discovery-calls', adminAuthMiddleware, (req: Request, res: Response) => {
  res.json(db.getDiscoveryBookings());
});

app.post('/api/discovery-calls', (req: Request, res: Response) => {
  const { name, email, date, timeSlot, serviceTopic } = req.body;
  if (!name || !email || !date || !timeSlot || !serviceTopic) {
    res.status(400).json({ error: 'All fields are required.' });
    return;
  }
  const booking = db.createDiscoveryBooking(req.body);
  res.status(201).json({
    success: true,
    message: 'Discovery session booked. Calendar invitation dispatched.',
    bookingId: booking.id,
  });
});

// --- CLIENT INQUIRIES ---
app.get('/api/inquiries', adminAuthMiddleware, (req: Request, res: Response) => {
  res.json(db.getInquiries());
});

app.post('/api/inquiries', (req: Request, res: Response) => {
  const { clientName, email, serviceRequested, projectDescription } = req.body;
  if (!clientName || !email || !serviceRequested || !projectDescription) {
    res.status(400).json({ error: 'Please provide client name, email, service, and description.' });
    return;
  }
  const created = db.createInquiry(req.body);
  res.status(201).json({
    success: true,
    message: 'Your inquiry has been registered with RYVO. Our team will review and contact you shortly.',
    inquiryId: created.id,
  });
});

app.put('/api/inquiries/:id', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const updated = db.updateInquiry(req.params.id, req.body, adminEmail);
  if (!updated) {
    res.status(404).json({ error: 'Inquiry not found' });
    return;
  }
  res.json(updated);
});

app.delete('/api/inquiries/:id', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const success = db.deleteInquiry(req.params.id, adminEmail);
  if (!success) {
    res.status(404).json({ error: 'Inquiry not found' });
    return;
  }
  res.json({ success: true });
});

// --- CONTACT MESSAGES ---
app.get('/api/contacts', adminAuthMiddleware, (req: Request, res: Response) => {
  res.json(db.getContacts());
});

app.post('/api/contacts', (req: Request, res: Response) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !subject || !message) {
    res.status(400).json({ error: 'All fields are required.' });
    return;
  }
  const created = db.createContact(req.body);
  res.status(201).json({ success: true, message: 'Message received. We will get back to you shortly.', id: created.id });
});

app.put('/api/contacts/:id', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const updated = db.updateContact(req.params.id, req.body, adminEmail);
  if (!updated) {
    res.status(404).json({ error: 'Contact message not found' });
    return;
  }
  res.json(updated);
});

app.delete('/api/contacts/:id', adminAuthMiddleware, (req: Request, res: Response) => {
  const adminEmail = (req as any).user.email;
  const success = db.deleteContact(req.params.id, adminEmail);
  if (!success) {
    res.status(404).json({ error: 'Contact message not found' });
    return;
  }
  res.json({ success: true });
});

// --- NEWSLETTER ---
app.get('/api/newsletter', adminAuthMiddleware, (req: Request, res: Response) => {
  res.json(db.getNewsletters());
});

app.post('/api/newsletter', (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    res.status(400).json({ error: 'Valid email required.' });
    return;
  }
  const result = db.subscribeNewsletter(email);
  res.json(result);
});

// --- AUDIT LOGS ---
app.get('/api/audit-logs', adminAuthMiddleware, (req: Request, res: Response) => {
  res.json(db.getAuditLogs());
});

// --- ANALYTICS ---
app.get('/api/analytics', (req: Request, res: Response) => {
  res.json(db.getAnalyticsSummary());
});

app.post('/api/analytics/track-view', (req: Request, res: Response) => {
  const { page } = req.body;
  if (page) {
    db.recordPageView(page);
  }
  res.json({ success: true });
});

app.post('/api/analytics/track-event', (req: Request, res: Response) => {
  const { type, label } = req.body;
  if (type && label) {
    db.trackEvent(type, label);
  }
  res.json({ success: true });
});

// --- MEDIA UPLOAD ---
app.post('/api/upload', adminAuthMiddleware, (req: Request, res: Response) => {
  const { dataUrl, filename } = req.body;
  if (!dataUrl || !filename) {
    res.status(400).json({ error: 'dataUrl and filename required.' });
    return;
  }
  try {
    const matches = dataUrl.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
    if (!matches || matches.length !== 3) {
      res.status(400).json({ error: 'Invalid base64 data URL.' });
      return;
    }
    const buffer = Buffer.from(matches[2], 'base64');
    const ext = path.extname(filename) || '.png';
    const safeName = `upload-${Date.now()}-${Math.floor(Math.random() * 10000)}${ext}`;
    const filePath = path.join(UPLOADS_DIR, safeName);
    fs.writeFileSync(filePath, buffer);
    const publicUrl = `/uploads/${safeName}`;
    res.json({ url: publicUrl, filename: safeName });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to save media upload: ' + err.message });
  }
});

// --- PREVIEW URL HEADER CHECKER ---
app.get('/api/check-frame', async (req: Request, res: Response) => {
  const targetUrl = req.query.url as string;
  if (!targetUrl) {
    res.status(400).json({ canEmbed: false, error: 'URL required' });
    return;
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const headRes = await fetch(targetUrl, {
      method: 'HEAD',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; RyvoBot/1.0)' },
    });
    clearTimeout(timeout);

    const xFrame = headRes.headers.get('x-frame-options');
    const csp = headRes.headers.get('content-security-policy');

    let canEmbed = true;
    let reason = '';

    if (xFrame) {
      const val = xFrame.toUpperCase();
      if (val.includes('DENY') || val.includes('SAMEORIGIN')) {
        canEmbed = false;
        reason = `X-Frame-Options: ${xFrame}`;
      }
    }

    if (csp && csp.toLowerCase().includes('frame-ancestors')) {
      canEmbed = false;
      reason = 'CSP frame-ancestors restrictions';
    }

    res.json({ canEmbed, reason, status: headRes.status });
  } catch (e: any) {
    res.json({ canEmbed: false, reason: 'Failed to verify headers or timeout' });
  }
});

// ==========================================
// VITE DEV SERVER OR STATIC PRODUCTION
// ==========================================
async function startServer() {
  if (!isProduction) {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`RYVO Agency full-stack engine running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to boot RYVO server:', err);
  process.exit(1);
});

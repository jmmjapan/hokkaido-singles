require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const nodemailer = require('nodemailer');
const path = require('path');
const upload = multer({ storage: multer.memoryStorage() });
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// DB操作用クライアント（service key・ログイン状態を持たせない）
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } }
);

// ログイン認証専用クライアント（こっちでサインインする）
const supabaseAuth = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } }
);
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ── 会員登録 ──
app.post('/api/register', upload.single('id_document'), async (req, res) => {
  const { email, password, nickname, full_name, birth_date, gender, occupation } = req.body;
  try {
    const password_hash = await bcrypt.hash(password, 10);
    const { data, error } = await supabase
      .from('users')
      .insert([{ email, password_hash, nickname, full_name, birth_date, gender, occupation }])
      .select();
    if (error) return res.status(400).json({ error: error.message });

    if (req.file) {
      const fileName = `${data[0].id}_${Date.now()}_${req.file.originalname}`;
      const { error: uploadError } = await supabase.storage
        .from('id-documents')
        .upload(fileName, req.file.buffer, { contentType: req.file.mimetype });
      if (!uploadError) {
        await supabase.from('users').update({ id_document_url: fileName }).eq('id', data[0].id);
      }
    }

    // 申込受付メールを送信
    await transporter.sendMail({
      from: `"Hokkaido Singles" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: '【Hokkaido Singles】お申し込みを受け付けました',
      html: `
        <p>${nickname} さん</p>
        <p>Hokkaido Singles へのお申し込みありがとうございます。</p>
        <p>24時間以内に審査結果をご連絡いたします。</p>
        <br>
        <p>Hokkaido Singles 運営事務局</p>
      `
    });

    res.json({ message: '登録完了。審査をお待ちください。', user: data[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── ログイン ──
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: authData, error: authError } = await supabaseAuth.auth.signInWithPassword({
      email,
      password
    });
    if (authError || !authData.user) {
      return res.status(400).json({ error: 'メールアドレスまたはパスワードが違います' });
    }
    const token = jwt.sign(
      { id: authData.user.id, is_admin: true },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ token, user: { id: authData.user.id, email: authData.user.email } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── 会員一覧（管理者用）──
app.get('/api/admin/users', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '認証が必要です' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.is_admin) return res.status(403).json({ error: '管理者権限が必要です' });
   const { data, error } = await supabase.from('users').select('*').order('created_at', { ascending: false });
if (error) { console.log('DB ERROR:', error); return res.status(400).json({ error: error.message }); }
console.log('USERS COUNT:', data.length);
res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── 本人確認書類の署名付きURL取得（管理者用）──
app.get('/api/admin/users/:id/id-document', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '認証が必要です' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.is_admin) return res.status(403).json({ error: '管理者権限が必要です' });

    const { data: user, error } = await supabase
      .from('users')
      .select('id_document_url')
      .eq('id', req.params.id)
      .single();
    if (error || !user?.id_document_url) {
      return res.status(404).json({ error: '書類が見つかりません' });
    }

    const { data: signedData, error: signError } = await supabase.storage
      .from('id-documents')
      .createSignedUrl(user.id_document_url, 60);
    if (signError) return res.status(500).json({ error: signError.message });

    res.json({ url: signedData.signedUrl });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── 審査承認（管理者用）──
app.patch('/api/admin/users/:id/approve', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '認証が必要です' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.is_admin) return res.status(403).json({ error: '管理者権限が必要です' });
    const { data, error } = await supabase
      .from('users')
      .update({ status: 'approved' })
      .eq('id', req.params.id)
      .select();
    if (error) return res.status(400).json({ error: error.message });

    // 承認メールを送信
    await transporter.sendMail({
      from: `"Hokkaido Singles" <${process.env.EMAIL_USER}>`,
      to: data[0].email,
      subject: '【Hokkaido Singles】審査が完了しました',
      html: `
        <p>${data[0].nickname} さん</p>
        <p>審査が完了し、Hokkaido Singles への入会が承認されました。</p>
        <p>以下よりログインしてプロフィールを作成してください。</p>
        <p><a href="${process.env.BASE_URL || 'https://hokkaido-singles.vercel.app'}">Hokkaido Singles へログイン</a></p>
        <br>
        <p>Hokkaido Singles 運営事務局</p>
      `
    });

    res.json({ message: '承認しました', user: data[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── 審査否認（管理者用）──
app.patch('/api/admin/users/:id/reject', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '認証が必要です' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded.is_admin) return res.status(403).json({ error: '管理者権限が必要です' });
    const { data, error } = await supabase
      .from('users')
      .update({ status: 'rejected' })
      .eq('id', req.params.id)
      .select();
    if (error) return res.status(400).json({ error: error.message });

    // 否認メールを送信
    await transporter.sendMail({
      from: `"Hokkaido Singles" <${process.env.EMAIL_USER}>`,
      to: data[0].email,
      subject: '【Hokkaido Singles】審査結果のご連絡',
      html: `
        <p>${data[0].nickname} さん</p>
        <p>この度はHokkaido Singlesへお申し込みいただきありがとうございました。</p>
        <p>誠に申し訳ございませんが、今回は審査を通過することができませんでした。</p>
        <br>
        <p>Hokkaido Singles 運営事務局</p>
      `
    });

    res.json({ message: '否認しました', user: data[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
// ── 会員ログイン ──
app.post('/api/member/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();
    if (error || !user) return res.status(400).json({ error: 'メールアドレスまたはパスワードが違います' });
    if (user.status !== 'approved') return res.status(403).json({ error: '審査中または否認されています' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ error: 'メールアドレスまたはパスワードが違います' });
    const token = jwt.sign(
      { id: user.id, plan: user.plan, gender: user.gender },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token, user: { id: user.id, email: user.email, nickname: user.nickname, plan: user.plan, gender: user.gender } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── プロフィール取得 ──
app.get('/api/member/profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '認証が必要です' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { data, error } = await supabase
      .from('profiles')
      .select('*')
      .eq('user_id', decoded.id)
      .single();
    if (error) return res.json({});
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── プロフィール保存 ──
app.post('/api/member/profile', upload.single('photo'), async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '認証が必要です' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { nickname, bio, marriage_style, occupation_profile, education, income } = req.body;

    let photo_url = null;
    if (req.file) {
      const fileName = `${decoded.id}_${Date.now()}_${req.file.originalname}`;
      const { error: uploadError } = await supabase.storage
        .from('profile-photos')
        .upload(fileName, req.file.buffer, { contentType: req.file.mimetype });
      if (!uploadError) photo_url = fileName;
    }

    const profileData = { user_id: decoded.id, nickname, bio, marriage_style, occupation_profile, education, income, updated_at: new Date() };
    if (photo_url) profileData.photo_url = photo_url;

    const { data: existing } = await supabase.from('profiles').select('id').eq('user_id', decoded.id).single();
    let result;
    if (existing) {
      const { data, error } = await supabase.from('profiles').update(profileData).eq('user_id', decoded.id).select().single();
      if (error) return res.status(400).json({ error: error.message });
      result = data;
    } else {
      const { data, error } = await supabase.from('profiles').insert([profileData]).select().single();
      if (error) return res.status(400).json({ error: error.message });
      result = data;
    }
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
// ── Stripeサブスクリプション作成 ──
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

app.post('/api/create-subscription', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '認証が必要です' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { plan } = req.body;

    const { data: user } = await supabase
      .from('users')
      .select('email, stripe_customer_id')
      .eq('id', decoded.id)
      .single();

    let customerId = user.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email });
      customerId = customer.id;
      await supabase.from('users').update({ stripe_customer_id: customerId }).eq('id', decoded.id);
    }

    const priceId = plan === 'standard'
      ? process.env.STRIPE_PRICE_STANDARD
      : process.env.STRIPE_PRICE_LIGHT;

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      mode: 'subscription',
      success_url: `${process.env.BASE_URL || 'http://localhost:3000'}/profile.html?payment=success`,
      cancel_url: `${process.env.BASE_URL || 'http://localhost:3000'}/profile.html?payment=cancel`,
    });

    res.json({ url: session.url });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Stripe Webhook ──
app.post('/api/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || 'dummy');
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const customerId = session.customer;
    await supabase.from('users')
      .update({ payment_status: 'active' })
      .eq('stripe_customer_id', customerId);
  }
  res.json({ received: true });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`サーバー起動: http://localhost:${PORT}`));
import os
from datetime import datetime
from dataclasses import dataclass

import gradio as gr
from sqlalchemy import (create_engine, Column, Integer, String, Boolean, Float,
                        ForeignKey, DateTime, UniqueConstraint, func)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session
from passlib.hash import bcrypt
from dotenv import load_dotenv

# ---------- Config ----------
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///local.db")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@site.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False))
Base = declarative_base()

# ---------- Models ----------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user")
    claims = relationship("Claim", back_populates="user")

class Coupon(Base):
    __tablename__ = "coupons"
    id = Column(Integer, primary_key=True)
    code = Column(String(64), unique=True, nullable=False)
    discount = Column(Float, nullable=False)  # 0–100
    service = Column(String(255), nullable=False)  # medical service name
    active = Column(Boolean, default=True)
    claims = relationship("Claim", back_populates="coupon")

class Claim(Base):
    __tablename__ = "claims"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    coupon_id = Column(Integer, ForeignKey("coupons.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="claims")
    coupon = relationship("Coupon", back_populates="claims")
    __table_args__ = (UniqueConstraint("user_id", "coupon_id", name="uq_user_coupon"),)

Base.metadata.create_all(engine)

# ---------- Seeds ----------
def seed_admin():
    db = SessionLocal()
    try:
        if not db.query(User).filter_by(email=ADMIN_EMAIL).first():
            db.add(User(email=ADMIN_EMAIL, password_hash=bcrypt.hash(ADMIN_PASSWORD), role="admin"))
            db.commit()
    finally:
        db.close()

def seed_coupons():
    db = SessionLocal()
    try:
        if not db.query(Coupon).first():
            db.add_all([
                Coupon(code="GP10", discount=10, service="GP Visit", active=True),
                Coupon(code="DENT20", discount=20, service="Dental Cleaning", active=True),
                Coupon(code="PHARM15", discount=15, service="Pharmacy Discount", active=True),
            ])
            db.commit()
    finally:
        db.close()

seed_admin()
seed_coupons()

# ---------- Session ----------
@dataclass
class SessionUser:
    id: int | None
    email: str | None
    role: str | None

def ensure_logged_in(state: SessionUser):
    return state and state.id is not None

def is_admin(state: SessionUser):
    return ensure_logged_in(state) and state.role == "admin"

# For cleaner UI inputs
MEDICAL_SERVICES = [
    "GP Visit", "Dental Cleaning", "Physiotherapy", "Pharmacy Discount",
    "Eye Exam", "Specialist Consultation"
]

# ---------- Auth ----------
def register(email, password, confirm, state: SessionUser):
    email = (email or "").strip().lower()
    if not email or not password:
        return gr.update(), "Email and password required.", state
    if "@" not in email:
        return gr.update(), "Invalid email.", state
    if password != confirm:
        return gr.update(), "Passwords do not match.", state
    if len(password) < 6:
        return gr.update(), "Password must be at least 6 characters.", state

    db = SessionLocal()
    try:
        if db.query(User).filter_by(email=email).first():
            return gr.update(), "Email already registered.", state
        user = User(email=email, password_hash=bcrypt.hash(password), role="user")
        db.add(user)
        db.commit()
        return gr.update(), "Registered! Please log in.", state
    finally:
        db.close()

def login(email, password, state: SessionUser):
    email = (email or "").strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter_by(email=email).first()
        if not user or not bcrypt.verify(password, user.password_hash):
            return SessionUser(None, None, None), "Invalid credentials."
        return SessionUser(user.id, user.email, user.role), f"Welcome, {user.email}!"
    finally:
        db.close()

def logout(state: SessionUser):
    return SessionUser(None, None, None), "Logged out."

# ---------- Admin CRUD ----------
def list_coupons_admin(state: SessionUser):
    if not is_admin(state):
        return "Unauthorized.", []
    db = SessionLocal()
    try:
        items = db.query(Coupon).order_by(Coupon.id.desc()).all()
        rows = [[c.id, c.code, c.discount, c.service, c.active] for c in items]
        return "", rows
    finally:
        db.close()

def _norm_coupon_inputs(code, discount, service):
    try:
        discount = float(discount)
    except:
        return None, None, None, "Discount must be a number."
    if not (0 < discount <= 100):
        return None, None, None, "Discount must be between 0 and 100."
    code = (code or "").strip().upper()
    service = (service or "").strip()
    if not code or not service:
        return None, None, None, "All fields required."
    return code, discount, service, None

def add_coupon(code, discount, service, active, state: SessionUser):
    if not is_admin(state):
        return "Unauthorized."
    code, discount, service, err = _norm_coupon_inputs(code, discount, service)
    if err: return err
    db = SessionLocal()
    try:
        if db.query(Coupon).filter_by(code=code).first():
            return "Code already exists."
        db.add(Coupon(code=code, discount=discount, service=service, active=bool(active)))
        db.commit()
        return "Coupon added."
    finally:
        db.close()

def edit_coupon(coupon_id, code, discount, service, active, state: SessionUser):
    if not is_admin(state):
        return "Unauthorized."
    db = SessionLocal()
    try:
        c = db.query(Coupon).get(int(coupon_id))
        if not c:
            return "Not found."
        # Only update provided fields
        if code:
            new_code = code.strip().upper()
            if new_code != c.code and db.query(Coupon).filter_by(code=new_code).first():
                return "Code already exists."
            c.code = new_code
        if discount is not None:
            try:
                val = float(discount)
            except:
                return "Discount must be a number."
            if not (0 < val <= 100):
                return "Discount must be between 0 and 100."
            c.discount = val
        if service:
            c.service = service.strip()
        if active is not None:
            c.active = bool(active)
        db.commit()
        return "Updated."
    finally:
        db.close()

def delete_coupon(coupon_id, state: SessionUser):
    if not is_admin(state):
        return "Unauthorized."
    db = SessionLocal()
    try:
        c = db.query(Coupon).get(int(coupon_id))
        if not c:
            return "Not found."

        # Remove all user claims for this coupon first (DB-agnostic)
        removed = db.query(Claim).filter(Claim.coupon_id == c.id).delete(synchronize_session=False)

        db.delete(c)
        db.commit()
        return f"Deleted coupon and removed {removed} related claim(s)."
    finally:
        db.close()


# ---------- User flows ----------
MAX_CLAIMS = 2

def _claims_left(user_id):
    db = SessionLocal()
    try:
        used = db.query(func.count(Claim.id)).filter(Claim.user_id == user_id).scalar() or 0
        return max(0, MAX_CLAIMS - used)
    finally:
        db.close()

def list_available_coupons(state: SessionUser):
    if not ensure_logged_in(state):
        return "Please log in.", [], "Remaining claims: 0"
    db = SessionLocal()
    try:
        coupons = db.query(Coupon).filter(Coupon.active == True).order_by(Coupon.id.desc()).all()
        rows = [[c.id, c.code, c.discount, c.service] for c in coupons]
        return "", rows, f"Remaining claims: {_claims_left(state.id)}"
    finally:
        db.close()

def my_claims(state: SessionUser):
    if not ensure_logged_in(state):
        return "Please log in.", []
    db = SessionLocal()
    try:
        claims = (db.query(Claim)
                    .filter(Claim.user_id == state.id)
                    .order_by(Claim.created_at.desc()).all())
        rows = [[cl.coupon.code, cl.coupon.discount, cl.coupon.service, cl.created_at.isoformat()] for cl in claims]
        return f"Remaining claims: {_claims_left(state.id)}", rows
    finally:
        db.close()

def claim_coupon(coupon_id, state: SessionUser):
    if not ensure_logged_in(state):
        return "Please log in to claim."
    db = SessionLocal()
    try:
        if _claims_left(state.id) <= 0:
            return "Claim limit reached (max 2)."
        coupon = db.query(Coupon).get(int(coupon_id))
        if not coupon or not coupon.active:
            return "Coupon not available."
        if db.query(Claim).filter_by(user_id=state.id, coupon_id=coupon.id).first():
            return "You already claimed this coupon."
        db.add(Claim(user_id=state.id, coupon_id=coupon.id))
        db.commit()
        return f"Claimed: {coupon.code} ({coupon.discount}% off {coupon.service})"
    finally:
        db.close()

# ---------- UI ----------
with gr.Blocks(title="Medical Coupons (SQLite Demo)") as demo:
    state = gr.State(SessionUser(None, None, None))
    gr.Markdown("## Medical Coupon Portal\nPrototype: Register/Login, Admin CRUD, User Claims (max 2). Using **SQLite**.")

    with gr.Tab("Auth"):
        with gr.Row():
            with gr.Column():
                gr.Markdown("### Register")
                reg_email = gr.Textbox(label="Email")
                reg_pw = gr.Textbox(label="Password", type="password")
                reg_pw2 = gr.Textbox(label="Confirm Password", type="password")
                reg_btn = gr.Button("Register")
                reg_msg = gr.Markdown("")
            with gr.Column():
                gr.Markdown("### Login")
                log_email = gr.Textbox(label="Email")
                log_pw = gr.Textbox(label="Password", type="password")
                log_btn = gr.Button("Login")
                login_msg = gr.Markdown("")
                logout_btn = gr.Button("Logout")

        reg_btn.click(register, [reg_email, reg_pw, reg_pw2, state], [reg_msg, state])
        log_btn.click(login, [log_email, log_pw, state], [state, login_msg])
        logout_btn.click(lambda s: logout(s), [state], [state, login_msg])

    with gr.Tab("Admin (Coupons)"):
        admin_info = gr.Markdown("Admin only: add / edit / delete coupons.")
        admin_table = gr.Dataframe(
            headers=["ID", "Code", "Discount %", "Service", "Active"],
            datatype=["number", "str", "number", "str", "bool"],
            row_count=0,
            interactive=False,
            label="All Coupons",
        )
        refresh_btn = gr.Button("Refresh List")

        with gr.Accordion("Add Coupon", open=False):
            add_code = gr.Textbox(label="Code (e.g., DENT20)")
            add_discount = gr.Number(label="Discount %", value=10)
            add_service = gr.Dropdown(choices=MEDICAL_SERVICES, value="GP Visit", label="Service")
            add_active = gr.Checkbox(label="Active", value=True)
            add_btn = gr.Button("Add")
            add_msg = gr.Markdown("")

        with gr.Accordion("Edit / Delete", open=False):
            edit_id = gr.Number(label="Coupon ID")
            edit_code = gr.Textbox(label="New Code (optional)")
            edit_discount = gr.Number(label="New Discount % (optional)")
            edit_service = gr.Dropdown(choices=MEDICAL_SERVICES, label="New Service (optional)", value=None)
            edit_active = gr.Checkbox(label="Active?")
            save_btn = gr.Button("Save Changes")
            del_btn = gr.Button("Delete")
            edit_msg = gr.Markdown("")

        refresh_btn.click(list_coupons_admin, [state], [admin_info, admin_table])
        add_btn.click(add_coupon, [add_code, add_discount, add_service, add_active, state], [add_msg]).then(
            list_coupons_admin, [state], [admin_info, admin_table]
        )
        save_btn.click(edit_coupon, [edit_id, edit_code, edit_discount, edit_service, edit_active, state], [edit_msg]).then(
            list_coupons_admin, [state], [admin_info, admin_table]
        )
        del_btn.click(delete_coupon, [edit_id, state], [edit_msg]).then(
            list_coupons_admin, [state], [admin_info, admin_table]
        )

    with gr.Tab("User (Claim)"):
        note = gr.Markdown("Claim up to **2** coupons total.")
        remain = gr.Markdown("Remaining claims: 0")
        list_table = gr.Dataframe(
            headers=["ID", "Code", "Discount %", "Service"],
            datatype=["number", "str", "number", "str"],
            row_count=0,
            interactive=False,
            label="Available Coupons",
        )
        reload_btn = gr.Button("Reload")
        claim_id = gr.Number(label="Coupon ID to claim")
        claim_btn = gr.Button("Claim")
        claim_msg = gr.Markdown("")

        my_claims_table = gr.Dataframe(
            headers=["Code", "Discount %", "Service", "Claimed At UTC"],
            row_count=0,
            interactive=False,
            label="My Claims",
        )
        my_reload = gr.Button("Reload My Claims")

        reload_btn.click(list_available_coupons, [state], [note, list_table, remain])
        my_reload.click(my_claims, [state], [remain, my_claims_table])
        claim_btn.click(claim_coupon, [claim_id, state], [claim_msg]).then(
            my_claims, [state], [remain, my_claims_table]
        )

demo.launch()

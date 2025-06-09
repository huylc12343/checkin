import os
import secrets
import hashlib
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import json

# --- CẤU HÌNH NGƯỜI DÙNG VỚI MẬT KHẨU ĐÃ HASH (SHA256) ---
FAKE_USERS_DB = {
    "huy": {
        "username": "huy",
        "full_name": "Huy",
        "hashed_password": "6aa349efa13ea1404bf361b575e1a68ede286f9845150477ef2ff8b567471819", 
        "disabled": False,
    },
    "staff": {
        "username": "staff",
        "full_name": "Staff",
        "hashed_password": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", 
        "disabled": False,
    },
    "hoangshitposting": {
        "username": "hoangshitposting",
        "full_name": "Thu",
        "hashed_password": "4b9d517651f8a4754fbce4080b34528c579dcc62f3c5a6c51011503e87637b51", 
        "disabled": False,
    }
}

# Nơi lưu trữ các session token đang hoạt động (lưu trên RAM của server)
ACTIVE_SESSIONS = {}

# --- CÁC HÀM XỬ LÝ XÁC THỰC "THỦ CÔNG" ---

def verify_password_simple(plain_password, hashed_password):
    """Băm mật khẩu người dùng nhập và so sánh với hash đã lưu."""
    password_hash = hashlib.sha256(plain_password.encode()).hexdigest()
    return password_hash == hashed_password

def create_session_token():
    """Tạo một session token ngẫu nhiên, an toàn."""
    return secrets.token_hex(32)

def get_current_user_from_session(authorization: str = Header(None)):
    """Lấy người dùng từ session token trong header."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
    )
    if authorization is None or not authorization.startswith("Bearer "):
        raise credentials_exception
    
    token = authorization.split("Bearer ")[1]
    
    username = ACTIVE_SESSIONS.get(token)
    if username is None:
        raise credentials_exception
        
    user = FAKE_USERS_DB.get(username)
    if user is None or user["disabled"]:
        raise credentials_exception
        
    return user

# --- CÁC MODEL DỮ LIỆU (Giữ nguyên) ---
class LoginRequest(BaseModel):
    username: str
    password: str

class User(BaseModel):
    username: str
    full_name: str | None = None

class CheckInRequest(BaseModel):
    order_code: str

# --- CẤU HÌNH GOOGLE SHEETS (Giữ nguyên) ---
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
SPREADSHEET_ID = '1kPEcrBZww8rxCxzPddnyNe7KQ7nZNERBOd29IIHCAf0'
SHEET_NAME = 'SHEETTEST'
# ... (Các chỉ số cột giữ nguyên)
NAME_COLUMN_INDEX, EMAIL_COLUMN_INDEX, PHONE_COLUMN_INDEX = 1, 2, 3
TICKET_QUANTITY_COLUMN_INDEX, TICKET_TYPE_COLUMN_INDEX = 4, 6
ORDER_CODE_COLUMN_INDEX, CHECKIN_STATUS_COLUMN_INDEX = 7, 10
NOTE_COLUMN_INDEX, CHECKIN_TIME_COLUMN_INDEX, CHECKER_NAME_COLUMN_INDEX = 11, 12, 13

# --- KHỞI TẠO APP ---
app = FastAPI(title="Check-in API (Simple Auth)", version="2.2.0") # Nâng version
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def get_sheets_service():
    try:
        creds_json_str = os.environ.get('GOOGLE_CREDENTIALS_JSON')
        if not creds_json_str:
            raise ValueError("Biến môi trường GOOGLE_CREDENTIALS_JSON chưa được thiết lập.")
        
        creds_info = json.loads(creds_json_str)
        creds = service_account.Credentials.from_service_account_info(creds_info, scopes=SCOPES)
        service = build('sheets', 'v4', credentials=creds)
        return service.spreadsheets()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi xác thực Google Sheets: {e}")

# --- API ENDPOINTS ---

@app.post("/login", summary="Đăng nhập và lấy session token")
async def login(request: LoginRequest):
    user = FAKE_USERS_DB.get(request.username)
    if not user or not verify_password_simple(request.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    
    session_token = create_session_token()
    ACTIVE_SESSIONS[session_token] = user["username"]
    
    return {"session_token": session_token, "user_info": {"username": user["username"], "full_name": user["full_name"]}}

@app.post("/logout", summary="Đăng xuất và hủy session token")
async def logout(authorization: str = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1]
        if token in ACTIVE_SESSIONS:
            del ACTIVE_SESSIONS[token]
    return {"message": "Logged out successfully"}

# --- LOGIC LÕI VÀ API ENDPOINTS ĐÃ SỬA LỖI ---

def _get_ticket_info_internal(order_code: str):
    """Hàm này chỉ làm nhiệm vụ lấy dữ liệu từ Google Sheets, không xác thực."""
    sheet = get_sheets_service()
    try:
        result = sheet.values().get(spreadsheetId=SPREADSHEET_ID, range=f"{SHEET_NAME}!A2:N").execute()
        values = result.get('values', [])
        for i, row in enumerate(values):
            if len(row) > ORDER_CODE_COLUMN_INDEX and row[ORDER_CODE_COLUMN_INDEX] == order_code:
                is_checked_in = len(row) > CHECKIN_STATUS_COLUMN_INDEX and row[CHECKIN_STATUS_COLUMN_INDEX] != ''
                return {
                    "found": True, "order_code": order_code, "row_number": i + 2,
                    "customer_name": row[NAME_COLUMN_INDEX] if len(row) > NAME_COLUMN_INDEX else 'N/A',
                    "email": row[EMAIL_COLUMN_INDEX] if len(row) > EMAIL_COLUMN_INDEX else 'N/A',
                    "phone": row[PHONE_COLUMN_INDEX] if len(row) > PHONE_COLUMN_INDEX else 'N/A',
                    "ticket_quantity": row[TICKET_QUANTITY_COLUMN_INDEX] if len(row) > TICKET_QUANTITY_COLUMN_INDEX else 'N/A',
                    "ticket_type": row[TICKET_TYPE_COLUMN_INDEX] if len(row) > TICKET_TYPE_COLUMN_INDEX else 'N/A',
                    "note": row[NOTE_COLUMN_INDEX] if len(row) > NOTE_COLUMN_INDEX else '',
                    "is_checked_in": is_checked_in,
                    "checked_in_by": row[CHECKER_NAME_COLUMN_INDEX] if is_checked_in and len(row) > CHECKER_NAME_COLUMN_INDEX else None,
                    "checked_in_at": row[CHECKIN_TIME_COLUMN_INDEX] if is_checked_in and len(row) > CHECKIN_TIME_COLUMN_INDEX else None,
                }
        return None
    except HttpError as err:
        raise HTTPException(status_code=500, detail=f"Lỗi khi truy cập Google Sheets: {err}")

@app.get("/api/ticket/{order_code}")
def get_ticket_info(order_code: str, current_user: dict = Depends(get_current_user_from_session)):
    """API endpoint để tra cứu thông tin vé (được bảo vệ)."""
    ticket_info = _get_ticket_info_internal(order_code)
    if not ticket_info:
        raise HTTPException(status_code=404, detail=f"Không tìm thấy vé với mã '{order_code}'")
    return ticket_info

@app.post("/api/checkin")
def check_in_ticket(request: CheckInRequest, current_user: dict = Depends(get_current_user_from_session)):
    """API endpoint để check-in vé (được bảo vệ)."""
    checker_name = current_user["full_name"]
    
    ticket_info = _get_ticket_info_internal(request.order_code)

    if not ticket_info:
        raise HTTPException(status_code=404, detail=f"Không tìm thấy vé với mã '{request.order_code}' để check-in")

    if ticket_info['is_checked_in']:
        raise HTTPException(status_code=400, detail="Vé này đã được check-in từ trước.")

    sheet = get_sheets_service()
    row_number_in_sheet = ticket_info['row_number']
    try:
        current_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        existing_note = ticket_info.get('note', '') 
        update_data = [['x', existing_note, current_time, checker_name]]
        update_range = f"{SHEET_NAME}!K{row_number_in_sheet}:N{row_number_in_sheet}"
        
        sheet.values().update(
            spreadsheetId=SPREADSHEET_ID, 
            range=update_range, 
            valueInputOption="USER_ENTERED", 
            body={"values": update_data}
        ).execute()

        return {"success": True, "message": f"Đã check-in thành công cho vé '{request.order_code}'."}
    except HttpError as err:
        raise HTTPException(status_code=500, detail=f"Lỗi khi cập nhật Google Sheets: {err}")
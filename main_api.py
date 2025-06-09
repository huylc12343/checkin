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
# Mật khẩu được hash bằng thuật toán SHA256.
# Đây là cách hash cơ bản, an toàn hơn plain text nhưng kém an toàn hơn bcrypt.
FAKE_USERS_DB = {
    "huy": {
        "username": "huy",
        "full_name": "Huy",
        "hashed_password": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", # Mật khẩu là "123"
        "disabled": False,
    },
    "staff": {
        "username": "staff",
        "full_name": "Staff",
        "hashed_password": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", # Mật khẩu là "password"
        "disabled": False,
    },
    "hoangshitposting": {
        "username": "hoangshitposting",
        "full_name": "Thu",
        "hashed_password": "2b29aab364440e57aff30a8d631f05f4b6dccaacda978419f105790ae0255feb", # Mật khẩu là "123"
        "disabled": False,
    }
}

# Nơi lưu trữ các session token đang hoạt động (lưu trên RAM của server)
# Key: session_token, Value: username
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
app = FastAPI(title="Check-in API (Simple Auth)", version="2.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def get_sheets_service():
    try:
        # Lấy thông tin credentials từ biến môi trường GOOGLE_CREDENTIALS_JSON
        creds_json_str = os.environ.get('GOOGLE_CREDENTIALS_JSON')
        if not creds_json_str:
            raise ValueError("Biến môi trường GOOGLE_CREDENTIALS_JSON chưa được thiết lập.")
        
        # Chuyển chuỗi JSON thành dictionary
        creds_info = json.loads(creds_json_str)
        
        # Tạo credentials từ dictionary
        creds = service_account.Credentials.from_service_account_info(creds_info, scopes=SCOPES)
        
        service = build('sheets', 'v4', credentials=creds)
        return service.spreadsheets()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi xác thực Google Sheets: {e}")
# --- API ENDPOINTS MỚI ---

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

# --- CÁC ENDPOINT CŨ ĐƯỢC BẢO VỆ BẰNG PHƯƠNG PHÁP MỚI ---

@app.get("/api/ticket/{order_code}")
def get_ticket_info(order_code: str, current_user: dict = Depends(get_current_user_from_session)):
    # ... (Logic hàm này giữ nguyên)
    sheet = get_sheets_service()
    # ... (toàn bộ code bên trong không đổi)
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
        raise HTTPException(status_code=404, detail=f"Không tìm thấy vé với mã '{order_code}'")
    except HttpError as err:
        raise HTTPException(status_code=500, detail=f"Lỗi khi truy cập Google Sheets: {err}")


@app.post("/api/checkin")
def check_in_ticket(request: CheckInRequest, current_user: dict = Depends(get_current_user_from_session)):
    checker_name = current_user["full_name"]
    # ... (Logic hàm này giữ nguyên)
    # Vì get_ticket_info cần user, chúng ta truyền nó vào
    ticket_info = get_ticket_info(request.order_code, current_user)
    if ticket_info['is_checked_in']:
        raise HTTPException(status_code=400, detail="Vé này đã được check-in từ trước.")
    sheet = get_sheets_service()
    row_number_in_sheet = ticket_info['row_number']
    try:
        current_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        existing_note = ticket_info.get('note', '') 
        update_data = [['x', existing_note, current_time, checker_name]]
        update_range = f"{SHEET_NAME}!K{row_number_in_sheet}:N{row_number_in_sheet}"
        sheet.values().update(spreadsheetId=SPREADSHEET_ID, range=update_range, valueInputOption="USER_ENTERED", body={"values": update_data}).execute()
        return {"success": True, "message": f"Đã check-in thành công cho vé '{request.order_code}'."}
    except HttpError as err:
        raise HTTPException(status_code=500, detail=f"Lỗi khi cập nhật Google Sheets: {err}")
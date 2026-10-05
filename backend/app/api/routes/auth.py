from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user
from app.core.config import settings
from app.core.security import verify_password, create_access_token
from app.models.user import User
from app.models.audit_log import AuditLog
from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.user import UserRead

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
def login(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == login_data.username).first()
    
    client_ip = request.client.host if request.client else "unknown"

    if not user or not verify_password(login_data.password, user.hashed_password):
        # Record failed audit log
        audit = AuditLog(
            actor=login_data.username,
            action="USER_LOGIN_FAILED",
            target=client_ip,
            result="FAILURE",
            metadata_info={"reason": "Invalid credentials", "ip": client_ip}
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        audit = AuditLog(
            actor=user.username,
            action="USER_LOGIN_INACTIVE",
            target=client_ip,
            result="DENIED",
            metadata_info={"reason": "User is inactive", "ip": client_ip}
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Please contact your SOC administrator.",
        )
    
    expires_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    access_token = create_access_token(
        subject=user.username,
        role=user.role,
        expires_delta=timedelta(minutes=expires_minutes)
    )

    # Record successful audit log
    audit = AuditLog(
        actor=user.username,
        action="USER_LOGIN_SUCCESS",
        target=client_ip,
        result="SUCCESS",
        metadata_info={"role": user.role, "ip": client_ip}
    )
    db.add(audit)
    db.commit()

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_minutes * 60,
        user=UserRead.model_validate(user)
    )


@router.get("/me", response_model=UserRead)
def read_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    return UserRead.model_validate(current_user)

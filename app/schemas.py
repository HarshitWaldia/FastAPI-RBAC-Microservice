from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime

# USER SCHEMAS
class UserBase(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    role: Optional[str] = "customer"

class UserCreate(UserBase):
    password: str


class AdminCreate(UserCreate):
    """Schema for creating an admin user. Includes a server-side secret to authorize admin creation."""
    admin_secret: str

class UserUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None

class User(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

# ADDRESS SCHEMAS
class AddressBase(BaseModel):
    street: str
    city: str
    state: str
    country: str
    postal_code: str

class AddressUpdate(BaseModel):
    street: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    postal_code: Optional[str] = None

class Address(AddressBase):
    id: int
    user_id: int

class AddressCreate(AddressBase):
    pass

    class Config:
        from_attributes = True

# CATEGORY SCHEMAS
class CategoryBase(BaseModel):
    name: str
    description: Optional[str] = None

class Category(CategoryBase):
    id: int

    class Config:
        from_attributes = True

class CategoryCreate(CategoryBase):
    pass

# PRODUCT SCHEMAS
class ProductBase(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    stock: int
    category_id: int
    seller_id: Optional[int] = None

class Product(ProductBase):
    id: int
    seller: Optional[User] = None

    class Config:
        from_attributes = True

# CART SCHEMAS
class CartItemBase(BaseModel):
    product_id: int
    quantity: int

class CartItem(CartItemBase):
    id: int
    cart_id: int
    product: Product

    class Config:
        from_attributes = True

class Cart(BaseModel):
    id: int
    user_id: int
    items: List[CartItem] = []

    class Config:
        from_attributes = True

# ORDER SCHEMAS
class OrderFromCart(BaseModel):
    cart_id: int
    address_id: int

class OrderItemBase(BaseModel):
    product_id: int
    quantity: int
    price: float

class OrderItem(OrderItemBase):
    id: int
    order_id: int
    product: Product

    class Config:
        from_attributes = True

class OrderBase(BaseModel):
    address_id: int
    total_amount: float

class Order(OrderBase):
    id: int
    user_id: int
    status: str
    created_at: datetime
    items: List[OrderItem] = []

    class Config:
        from_attributes = True

# REVIEW SCHEMAS
class ReviewBase(BaseModel):
    product_id: int
    rating: int
    comment: Optional[str] = None

class ReviewCreate(ReviewBase):
    pass

class ReviewResponse(ReviewBase):
    id: int
    user_id: int
    created_at: datetime

    class Config:
        from_attributes = True

# WISHLIST SCHEMAS
class WishlistBase(BaseModel):
    product_id: int

class WishlistCreate(WishlistBase):
    pass

class WishlistResponse(WishlistBase):
    id: int
    user_id: int
    product: Product

    class Config:
        from_attributes = True

# AUTH SCHEMAS
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: int
    email: Optional[str] = None
    role: Optional[str] = None

    class Config:
        from_attributes = True

# SHIPMENT SCHEMAS
class ShipmentBase(BaseModel):
    order_id: int
    tracking_number: Optional[str] = None
    carrier: Optional[str] = None
    status: Optional[str] = None

class ShipmentCreate(ShipmentBase):
    pass

class ShipmentResponse(ShipmentBase):
    id: int

    class Config:
        from_attributes = True

from sqlalchemy.orm import Session
from passlib.context import CryptContext
from typing import List, Optional

from . import models, schemas
from datetime import datetime

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# USER CRUD
def get_user_by_email(db: Session, email: str) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate) -> models.User:
    db_user = models.User(
        name=user.name,
        email=user.email,
        password=hash_password(user.password),
        phone=user.phone,
        role=user.role or "customer"
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_users(db: Session, skip: int = 0, limit: int = 100) -> List[models.User]:
    return db.query(models.User).offset(skip).limit(limit).all()

def get_user(db: Session, user_id: int) -> Optional[models.User]:
    return db.query(models.User).filter(models.User.id == user_id).first()

def update_user(db: Session, user: models.User, update: schemas.UserUpdate) -> models.User:
    if update.name:
        user.name = update.name
    if update.phone:
        user.phone = update.phone
    if update.password:
        user.password = hash_password(update.password)
    if update.role:
        user.role = update.role
    db.commit()
    db.refresh(user)
    return user

def del_user(db: Session, user_id: int) -> Optional[models.User]:
    user = get_user(db, user_id)
    if user:
        db.delete(user)
        db.commit()
    return user

# PRODUCT CRUD
def get_products(db: Session, skip: int = 0, limit: int = 100) -> List[models.Product]:
    return db.query(models.Product).offset(skip).limit(limit).all()

def get_product(db: Session, product_id: int) -> Optional[models.Product]:
    return db.query(models.Product).filter(models.Product.id == product_id).first()

def create_product(db: Session, product: schemas.ProductBase, seller_id: int = None) -> models.Product:
    # Prevent client-provided seller_id from being trusted. Start from product dict
    product_data = product.dict()
    # Remove any seller_id supplied by client to avoid privilege escalation
    product_data.pop("seller_id", None)
    # If an explicit seller_id is provided by the server-side caller, use it
    if seller_id is not None:
        product_data["seller_id"] = seller_id
    db_product = models.Product(**product_data)
    db.add(db_product)
    db.commit()
    db.refresh(db_product)
    return db_product

def get_products_by_seller(db: Session, seller_id: int) -> List[models.Product]:
    return db.query(models.Product).filter(models.Product.seller_id == seller_id).all()

def update_product(db: Session, product_id: int, update: schemas.ProductBase, seller_id: int = None) -> Optional[models.Product]:
    product = db.query(models.Product).filter(models.Product.id == product_id).first()
    if not product:
        return None
    
    # If seller_id provided, check ownership
    if seller_id and product.seller_id != seller_id:
        return None
    
    for key, value in update.dict(exclude_unset=True).items():
        setattr(product, key, value)
    
    db.commit()
    db.refresh(product)
    return product

def delete_product(db: Session, product_id: int, user_id: int = None, user_role: str = None) -> Optional[models.Product]:
    product = db.query(models.Product).filter(models.Product.id == product_id).first()
    if not product:
        return None
    
    # Admin can delete any product, seller can only delete their own
    if user_role == "admin" or (user_role == "seller" and product.seller_id == user_id):
        db.delete(product)
        db.commit()
        return product
    
    return None

# CART CRUD
def get_cart(db: Session, user_id: int) -> Optional[models.Cart]:
    return db.query(models.Cart).filter(models.Cart.user_id == user_id).first()

def create_cart(db: Session, user_id: int) -> models.Cart:
    cart = models.Cart(user_id=user_id)
    db.add(cart)
    db.commit()
    db.refresh(cart)
    return cart

def add_cart_item(db: Session, cart_id: int, item: schemas.CartItemBase) -> models.CartItem:
    product = db.query(models.Product).filter(models.Product.id == item.product_id).first()
    if not product:
        raise ValueError("Product not found")

    if product.stock is not None and item.quantity > product.stock:
        raise ValueError("Insufficient stock")

    db_item = models.CartItem(cart_id=cart_id, **item.dict())
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

def update_cart_item(db: Session, cart_item_id: int, quantity: int) -> models.CartItem:
    item = db.query(models.CartItem).filter(models.CartItem.id == cart_item_id).first()
    if item:
        item.quantity = quantity
        db.commit()
        db.refresh(item)
    return item

def remove_cart_item(db: Session, cart_item_id: int) -> Optional[models.CartItem]:
    item = db.query(models.CartItem).filter(models.CartItem.id == cart_item_id).first()
    # if item:
    #     db.delete(item)
    #     db.commit()
    # return item
    if not item:
        return False
    db.delete(item)
    db.commit()
    return True


# ORDER CRUD
def create_order(db: Session, order: schemas.OrderBase, user_id: int, items: List[schemas.OrderItemBase]) -> models.Order:
    db_order = models.Order(user_id=user_id, address_id=order.address_id, total_amount=order.total_amount)
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    for i in items:
        db_item = models.OrderItem(order_id=db_order.id, **i.dict())
        db.add(db_item)
    db.commit()
    db.refresh(db_order)
    return db_order

def get_orders(db: Session, user_id: int) -> List[models.Order]:
    return db.query(models.Order).filter(models.Order.user_id == user_id).all()

def get_order(db: Session, order_id: int) -> Optional[models.Order]:
    return db.query(models.Order).filter(models.Order.id == order_id).first()

def create_order_from_cart_for_user(db: Session, user_id: int) -> models.Order:
    cart = db.query(models.Cart).filter(models.Cart.user_id == user_id).first()
    if not cart:
        raise ValueError("Cart not found for this user")

    address = db.query(models.Address).filter(models.Address.user_id == user_id).first()
    if not address:
        raise ValueError("Address not found for this user")

    cart_items = db.query(models.CartItem).filter(models.CartItem.cart_id == cart.id).all()
    if not cart_items:
        raise ValueError("Cart is empty")

    order = models.Order(user_id=user_id, address_id=address.id, total_amount=0)
    db.add(order)
    db.commit()
    db.refresh(order)

    total = 0
    for item in cart_items:
        order_item = models.OrderItem(
            order_id=order.id,
            product_id=item.product_id,
            quantity=item.quantity,
            price=item.product.price
        )
        db.add(order_item)
        total += item.quantity * item.product.price

    order.total_amount = total
    db.commit()
    db.refresh(order)

    # Clear the cart items now that the order has been placed
    for item in cart_items:
        # If cart items have relationships, remove them safely
        try:
            db.delete(item)
        except Exception:
            # fallback: ignore deletion error and continue
            pass
    db.commit()

    return order

# CATEGORY CRUD
def create_category(db: Session, category: schemas.CategoryCreate):
    db_category = models.Category(**category.model_dump())
    db.add(db_category)
    db.commit()
    db.refresh(db_category)
    return db_category

def get_categories(db: Session):
    return db.query(models.Category).all()

def update_category(db: Session, category_id: int, update: schemas.CategoryCreate):
    category = db.query(models.Category).filter(models.Category.id == category_id).first()
    if not category:
        return None
    
    for key, value in update.dict(exclude_unset=True).items():
        setattr(category, key, value)
    
    db.commit()
    db.refresh(category)
    return category

def delete_category(db: Session, category_id: int):
    category = db.query(models.Category).filter(models.Category.id == category_id).first()
    if not category:
        return None
    
    db.delete(category)
    db.commit()
    return category

# ADDRESS CRUD
def create_address(db: Session, user_id: int, address: schemas.AddressCreate):
    db_address = models.Address(user_id=user_id, **address.dict())
    db.add(db_address)
    db.commit()
    db.refresh(db_address)
    return db_address

def get_addresses(db: Session, user_id: int):
    return db.query(models.Address).filter(models.Address.user_id == user_id).all()

def get_address(db: Session, address_id: int):
    return db.query(models.Address).filter(models.Address.id == address_id).first()

def get_address_by_user(db: Session, user_id: int):
    return db.query(models.Address).filter(models.Address.user_id == user_id).first()

def update_address(db: Session, db_address: models.Address, update: schemas.AddressUpdate):
    for key, value in update.dict(exclude_unset=True).items():
        setattr(db_address, key, value)
    db.commit()
    db.refresh(db_address)
    return db_address

# WISHLIST
def add_to_wishlist(db: Session, user_id: int, product_id: int) -> models.Wishlist:
    exists = db.query(models.Wishlist).filter(
        models.Wishlist.user_id == user_id,
        models.Wishlist.product_id == product_id
    ).first()
    if exists:
        return exists
    item = models.Wishlist(user_id=user_id, product_id=product_id)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item

def get_wishlist(db: Session, user_id: int):
    return db.query(models.Wishlist).filter(models.Wishlist.user_id == user_id).all()

def remove_from_wishlist(db: Session, wishlist_id: int):
    item = db.query(models.Wishlist).filter(models.Wishlist.id == wishlist_id).first()
    if not item:
        return None
    db.delete(item)
    db.commit()
    return item

# REVIEWS 
def create_review(db: Session, user_id: int, review: schemas.ReviewCreate) -> models.Review:
    if review.rating < 1 or review.rating > 5:
        raise ValueError("rating must be between 1 and 5")
    db_review = models.Review(
        user_id=user_id,
        product_id=review.product_id,
        rating=review.rating,
        comment=review.comment
    )
    db.add(db_review)
    db.commit()
    db.refresh(db_review)
    return db_review

def get_reviews_for_product(db: Session, product_id: int):
    return db.query(models.Review).filter(models.Review.product_id == product_id).all()

# SHIPMENTS 
def create_shipment(db: Session, shipment_in: schemas.ShipmentCreate) -> models.Shipment:
    order = db.query(models.Order).filter(models.Order.id == shipment_in.order_id).first()
    if not order:
        raise ValueError("Order not found")
    db_shipment = models.Shipment(
        order_id=shipment_in.order_id,
        tracking_number=shipment_in.tracking_number,
        carrier=shipment_in.carrier,
        status=shipment_in.status or "preparing"
    )
    db.add(db_shipment)
    db.commit()
    db.refresh(db_shipment)
    return db_shipment

def get_shipment(db: Session, shipment_id: int):
    return db.query(models.Shipment).filter(models.Shipment.id == shipment_id).first()

def update_shipment_status(db: Session, shipment_id: int, status: str):
    shipment = db.query(models.Shipment).filter(models.Shipment.id == shipment_id).first()
    if not shipment:
        return None
    shipment.status = status
    db.commit()
    db.refresh(shipment)
    return shipment

def get_shipments(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Shipment).offset(skip).limit(limit).all()

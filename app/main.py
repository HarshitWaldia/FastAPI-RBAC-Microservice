from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List
from datetime import timedelta
from typing import Optional

from . import crud, models, schemas
import os
from .database import Local_Session, engine
from .auth import create_access_token, get_current_user, get_current_admin, get_current_seller, get_current_admin_or_seller

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="E-Commerce API Microservice",
    description="""
*A unified API powering the `core of modern e-commerce` — from users to orders.*\n
\n
---

**Version:** `1.0.0`  
**Author:** `Harshit Waldia`   
**Contact:** [harshitwaldia112@gmail.com](mailto:harshitwaldia112@gmail.com)

---
*Built with `engineering discipline` for `effortless scalability` and `maintainability`*.
""",
    version="1.0.0",
    openapi_tags=[
        {"name": "Home", "description": "General info endpoint."},
        {"name": "Auth", "description": "Authentication / sign-up / login endpoints."},
        {"name": "Users", "description": "User CRUD and profile endpoints."},
        {"name": "Addresses", "description": "User address management."},
        {"name": "Categories", "description": "Product category management."},
        {"name": "Products", "description": "Product listing and details."},
        {"name": "Seller Products", "description": "Seller-specific product management."},
        {"name": "Cart", "description": "Shopping cart endpoints."},
        {"name": "Orders", "description": "Order creation and retrieval."},
        {"name": "Wishlist", "description": "Wishlist management endpoints."},
        {"name": "Reviews", "description": "Product reviews."},
        {"name": "Shipments", "description": "Shipment creation and status management."},
    ],
)

# Dependency: DB session
def get_db():
    db = Local_Session()
    try:
        yield db
    finally:
        db.close()

# HOME
@app.get("/", tags=["Home"], summary="Welcome message")
def home():
    return {"Message": "Welcome To Mini E-Commerce FastAPI Tutorial"}

# SIGNUP
@app.post("/signup", response_model=schemas.User, status_code=201, tags=["Auth"], summary="Register a new user")
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Prevent creation of admin users via this public endpoint.
    if getattr(user, "role", None) == "admin":
        raise HTTPException(status_code=403, detail="Cannot create admin via this endpoint")

    # Only allow 'customer' or 'seller' roles through the public signup.
    if getattr(user, "role", None) and user.role not in ("customer", "seller"):
        raise HTTPException(status_code=400, detail="Invalid role")

    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)


@app.post("/admin/signup", response_model=schemas.User, status_code=201, tags=["Auth"], summary="Register a new admin (requires secret)")
def admin_signup(admin: schemas.AdminCreate, db: Session = Depends(get_db)):

    admin_key = os.getenv("ADMIN_CREATION_KEY")
    if not admin_key:
        raise HTTPException(status_code=500, detail="Admin creation key is not configured on the server")
    if admin.admin_secret != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin secret")

    db_user = crud.get_user_by_email(db, email=admin.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Force role to admin regardless of client-supplied value
    admin.role = "admin"
    return crud.create_user(db=db, user=admin)


# USER ENDPOINTS
@app.get("/users/", response_model=List[schemas.User], tags=["Users"], summary="List users (admin only)")
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db),current_user: models.User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this action")
    return crud.get_users(db, skip=skip, limit=limit)

@app.get("/users/{user_id}", response_model=schemas.User, tags=["Users"], summary="Get a user by ID (admin only)")
def read_user(user_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this action")
    db_user = crud.get_user(db, user_id=user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@app.put("/users/{user_id}", response_model=schemas.User, tags=["Users"], summary="Admin: Update a user")
def update_user(user_id: int, update: schemas.UserUpdate, db: Session = Depends(get_db), admin: models.User = Depends(get_current_admin)):
    """Admin-only: update any user's fields by user_id."""
    db_user = crud.get_user(db, user_id=user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return crud.update_user(db, user=db_user, update=update)

@app.delete("/users/{user_id}", response_model=schemas.User, tags=["Users"], summary="Admin: delete a user")
def delete_user(user_id: int, db: Session = Depends(get_db), admin: models.User = Depends(get_current_admin)):
    """Admin-only: delete a user by id."""
    db_user = crud.del_user(db, user_id=user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


# SELF (logged-in user) endpoints
# @app.put("/users/me", response_model=schemas.User, tags=["Users"], summary="Update current user's profile")
# def update_me(update: schemas.UserUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
#     db_user = crud.get_user(db, user_id=current_user.id)
#     if not db_user:
#         raise HTTPException(status_code=404, detail="User not found")
#     return crud.update_user(db, user=db_user, update=update)

@app.put("/users/", response_model=schemas.User, tags=["Users"], summary="Update a user")
def update_user(update: schemas.UserUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    # If the user is an authenticated user, use their ID
    if not current_user.id:
        raise HTTPException(status_code=403, detail="You are not authorized to modify this user")

    db_user = crud.get_user(db, user_id=current_user.id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return crud.update_user(db, user=db_user, update=update)


@app.delete("/users/", response_model=schemas.User, tags=["Users"], summary="Delete current user's account")
def delete_me(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    db_user = crud.del_user(db, user_id=current_user.id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

# ADMIN USER MANAGEMENT
@app.put("/admin/users/{user_id}/role", response_model=schemas.User, tags=["Users"], summary="Admin: update user role")
def admin_update_user_role(
    user_id: int,
    update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(get_current_admin)
):
    db_user = crud.get_user(db, user_id=user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if update.role and update.role not in ["customer", "seller", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    return crud.update_user(db, user=db_user, update=update)

# ADDRESS USER
@app.post("/addresses/", response_model=schemas.Address, tags=["Addresses"], summary="Add an address for current user")
def add_address(address: schemas.AddressCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return crud.create_address(db, user_id=current_user.id, address=address)

@app.post("/addresses/update", response_model=schemas.Address, tags=["Addresses"], summary="Update current user's address")
def update_address(
    update: schemas.AddressUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    db_address = crud.get_address_by_user(db, user_id=current_user.id)
    if not db_address:
        raise HTTPException(status_code=404, detail="Address not found")
    return crud.update_address(db=db, db_address=db_address, update=update)

@app.get("/addresses/", response_model=List[schemas.Address], tags=["Addresses"], summary="List current user's addresses")
def list_addresses(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return crud.get_addresses(db, user_id=current_user.id)

# CURRENT LOGGED-IN USER
@app.get("/me", response_model=schemas.User, tags=["Auth"], summary="Get current user profile")
def read_me(current_user: models.User = Depends(get_current_user)):
    return current_user

# LOGIN
@app.post("/login", response_model=schemas.Token, tags=["Auth"], summary="Obtain access token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, email=form_data.username)
    if not user or not crud.verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    access_token = create_access_token(
        data={"user_id": user.id, "email": user.email, "role": user.role},
        expires_delta=timedelta(minutes=60)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# CATEGORY ENDPOINTS
@app.post("/categories/", response_model=schemas.Category, tags=["Categories"], summary="Create a category")
def create_category(category: schemas.CategoryCreate, db: Session = Depends(get_db), admin_seller: models.User = Depends(get_current_admin_or_seller)):
    return crud.create_category(db, category=category)

@app.get("/categories/", response_model=list[schemas.Category], tags=["Categories"], summary="List categories")
def get_categories(db: Session = Depends(get_db)):
    return crud.get_categories(db)

@app.put("/categories/{category_id}", response_model=schemas.Category, tags=["Categories"], summary="Update a category")
def update_category(category_id: int, category: schemas.CategoryCreate, db: Session = Depends(get_db), admin_seller: models.User = Depends(get_current_admin_or_seller)):
    updated_category = crud.update_category(db, category_id=category_id, update=category)
    if not updated_category:
        raise HTTPException(status_code=404, detail="Category not found")
    return updated_category

@app.delete("/categories/{category_id}", tags=["Categories"], summary="Admin : Delete a category")
def delete_category(category_id: int, db: Session = Depends(get_db), admin: models.User = Depends(get_current_admin)):
    deleted_category = crud.delete_category(db, category_id=category_id)
    if not deleted_category:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"message": "Category deleted successfully"}

# PRODUCT ENDPOINTS
@app.get("/products/", response_model=List[schemas.Product], tags=["Products"], summary="List products")
def list_products(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return crud.get_products(db, skip=skip, limit=limit)

@app.get("/products/{product_id}", response_model=schemas.Product, tags=["Products"], summary="Get product details")
def get_product(product_id: int, db: Session = Depends(get_db)):
    product = crud.get_product(db, product_id=product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product

@app.post("/products/", response_model=schemas.Product, status_code=201, tags=["Products"], summary="Create a new product")
def create_product(product: schemas.ProductBase, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_admin_or_seller)):
    """
    Only sellers or admins can create products.
    - If the caller is a seller, the product will be assigned to that seller (seller_id forced).
    - If the caller is an admin, they may optionally include a seller_id in the request to assign the product; otherwise seller_id will be None.
    """
    if current_user.role == "seller":
        seller_id = current_user.id
    else:
        # admin: allow admin to optionally set seller_id in request body
        seller_id = product.seller_id if getattr(product, "seller_id", None) is not None else None

    return crud.create_product(db, product=product, seller_id=seller_id)

# SELLER PRODUCT ENDPOINTS
@app.get("/seller/products/", response_model=List[schemas.Product], tags=["Seller Products"], summary="Get seller products")
def seller_get_products(db: Session = Depends(get_db), seller: models.User = Depends(get_current_seller)):
    if seller.role == "admin":
        return crud.get_products(db)
    return crud.get_products_by_seller(db, seller_id=seller.id)

@app.put("/seller/products/{product_id}", response_model=schemas.Product, tags=["Seller Products"], summary="Seller: update a product")
def seller_update_product(
    product_id: int,
    product_update: schemas.ProductBase,
    db: Session = Depends(get_db),
    seller: models.User = Depends(get_current_seller)
):
    updated_product = crud.update_product(
        db, 
        product_id=product_id, 
        update=product_update, 
        seller_id=seller.id if seller.role == "seller" else None
    )
    if not updated_product:
        raise HTTPException(status_code=404, detail="Product not found or not authorized")
    return updated_product

@app.delete("/seller/products/{product_id}", tags=["Seller Products"], summary="Seller: delete a product")
def seller_delete_product(
    product_id: int,
    db: Session = Depends(get_db),
    seller: models.User = Depends(get_current_seller)
):
    deleted_product = crud.delete_product(db, product_id=product_id, user_id=seller.id, user_role=seller.role)
    if not deleted_product:
        raise HTTPException(status_code=404, detail="Product not found or not authorized")
    return {"message": "Product deleted successfully"}

# ADMIN PRODUCT MANAGEMENT
@app.delete("/admin/products/{product_id}", tags=["Products"], summary="Admin: delete any product")
def admin_delete_product(
    product_id: int,
    db: Session = Depends(get_db),
    admin: models.User = Depends(get_current_admin)
):
    deleted_product = crud.delete_product(db, product_id=product_id, user_id=admin.id, user_role=admin.role)
    if not deleted_product:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Product deleted successfully"}

# CART ENDPOINTS
@app.get("/cart/", response_model=schemas.Cart, tags=["Cart"], summary="Get current user's cart")
def get_cart(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    cart = crud.get_cart(db, user_id=current_user.id)
    if not cart:
        cart = crud.create_cart(db, user_id=current_user.id)
    return cart

@app.post("/cart/items", response_model=schemas.CartItem, tags=["Cart"], summary="Add item to current user's cart")
def add_item_to_cart(item: schemas.CartItemBase, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    cart = crud.get_cart(db, user_id=current_user.id)
    if not cart:
        cart = crud.create_cart(db, user_id=current_user.id)
    try:
        return crud.add_cart_item(db, cart_id=cart.id, item=item)
    except ValueError as e:
        msg = str(e).lower()
        if "not found" in msg:
            raise HTTPException(status_code=404, detail=str(e))
        if "insufficient" in msg:
            raise HTTPException(status_code=400, detail=str(e))
        raise HTTPException(status_code=400, detail=str(e))

@app.put("/cart/items/{cart_item_id}", response_model=schemas.CartItem, tags=["Cart"], summary="Update quantity of a cart item")
def update_cart_item(cart_item_id: int, quantity: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    item = crud.update_cart_item(db, cart_item_id=cart_item_id, quantity=quantity)
    if not item:
        raise HTTPException(status_code=404, detail="Cart item not found")
    if item.cart.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not allowed to modify this item")
    return item

@app.delete("/cart/items/{cart_item_id}", tags=["Cart"], summary="Remove an item from the cart")
def delete_cart_item(cart_item_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    # item = crud.remove_cart_item(db, cart_item_id)
    # if not item:
    #     raise HTTPException(status_code=404, detail="Cart item not found")
    # cart = db.query(models.Cart).filter(models.Cart.id == item.cart_id).first()
    # if item.cart.user_id != current_user.id and current_user.role != "admin":
    #     raise HTTPException(status_code=403, detail="Not allowed to delete this item")
    # crud.remove_cart_item(db, cart_item_id=cart_item_id)
    # return {"message": "Cart Item Deleted Successfully"}

    item = db.query(models.CartItem).filter(models.CartItem.id == cart_item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Cart item not found")
    cart = db.query(models.Cart).filter(models.Cart.id == item.cart_id).first()
    if not cart:
        raise HTTPException(status_code=404, detail="Cart not found")
    if cart.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not allowed to delete this item")

    # Step 4: Delete the item safely
    deleted = crud.remove_cart_item(db, cart_item_id=cart_item_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Cart item not found")

    return {"message": "Cart Item Deleted Successfully"}


# ORDER ENDPOINTS
@app.post("/orders/", response_model=schemas.Order, tags=["Orders"], summary="Create an order from the current user's cart")
def create_order_from_cart(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    try:
        return crud.create_order_from_cart_for_user(db=db, user_id=current_user.id)
    except ValueError as e:
        msg = str(e).lower()
        # Map resource-not-found errors to 404, empty cart to 400
        if "not found" in msg:
            raise HTTPException(status_code=404, detail=str(e))
        if "empty" in msg:
            raise HTTPException(status_code=400, detail=str(e))
        # fallback
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/orders/", response_model=List[schemas.Order], tags=["Orders"], summary="List orders for current user")
def get_orders(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return crud.get_orders(db, user_id=current_user.id)

@app.get("/orders/detail/{order_id}", response_model=schemas.Order, tags=["Orders"], summary="Get order detail")
def get_order(order_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    order = crud.get_order(db, order_id=order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not allowed to access this order")
    return order

# WISHLIST
@app.post("/wishlist/", response_model=schemas.WishlistResponse, status_code=201, tags=["Wishlist"], summary="Add a product to wishlist")
def add_to_wishlist_endpoint(w: schemas.WishlistCreate,
                             db: Session = Depends(get_db),
                             current_user: models.User = Depends(get_current_user)):
    item = crud.add_to_wishlist(db, user_id=current_user.id, product_id=w.product_id)
    return item

@app.get("/wishlist/", response_model=List[schemas.WishlistResponse], tags=["Wishlist"], summary="Get current user's wishlist")
def get_wishlist_endpoint(db: Session = Depends(get_db),current_user: models.User = Depends(get_current_user)):
    return crud.get_wishlist(db, user_id=current_user.id)

@app.delete("/wishlist/{wishlist_id}", status_code=204, tags=["Wishlist"], summary="Remove item from wishlist")
def remove_wishlist_endpoint(wishlist_id: int,db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    item = crud.remove_from_wishlist(db, wishlist_id)
    if not item:
        raise HTTPException(status_code=404, detail="Wishlist item not found")
    
    if item.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    return None

# REVIEWS
@app.post("/reviews/", response_model=schemas.ReviewResponse, status_code=201, tags=["Reviews"], summary="Add a review for a product")
def add_review_endpoint(review: schemas.ReviewCreate, db: Session = Depends(get_db),current_user: models.User = Depends(get_current_user)):
    try:
        db_review = crud.create_review(db, user_id=current_user.id, review=review)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return db_review

@app.get("/reviews/{product_id}", response_model=List[schemas.ReviewResponse], tags=["Reviews"], summary="Get reviews for a product")
def get_reviews_endpoint(product_id: int, db: Session = Depends(get_db)):
    return crud.get_reviews_for_product(db, product_id=product_id)

# SHIPMENTS
@app.post("/shipments/", response_model=schemas.ShipmentResponse, status_code=201, tags=["Shipments"], summary="Create a shipment")
def create_shipment_endpoint(shipment: schemas.ShipmentCreate,db: Session = Depends(get_db),admin_seller: models.User = Depends(get_current_admin_or_seller)):
    try:
        db_ship = crud.create_shipment(db, shipment)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return db_ship

@app.get("/shipments/", response_model=List[schemas.ShipmentResponse], tags=["Shipments"], summary="List shipments")
def get_shipments_endpoint(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), admin_seller: models.User = Depends(get_current_admin_or_seller)):
    return crud.get_shipments(db, skip=skip, limit=limit)

@app.get("/shipments/{shipment_id}", response_model=schemas.ShipmentResponse, tags=["Shipments"], summary="Get a shipment by ID")
def get_shipment_endpoint(shipment_id: int, db: Session = Depends(get_db), admin_seller: models.User = Depends(get_current_admin_or_seller)):
    ship = crud.get_shipment(db, shipment_id)
    if not ship:
        raise HTTPException(status_code=404, detail="Shipment not found")
    return ship

@app.put("/shipments/{shipment_id}", response_model=schemas.ShipmentResponse, tags=["Shipments"], summary="Update shipment status")
def update_shipment_endpoint(shipment_id: int, status: str,db: Session = Depends(get_db), admin_seller: models.User = Depends(get_current_admin_or_seller)):
    ship = crud.update_shipment_status(db, shipment_id=shipment_id, status=status)
    if not ship:
        raise HTTPException(status_code=404, detail="Shipment not found")
    return ship

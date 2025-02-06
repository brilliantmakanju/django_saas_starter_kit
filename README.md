# **Django SaaS Starter Kit**  

A robust, modular, and scalable Django-based starter kit designed to accelerate the development of SaaS applications. It incorporates user authentication, subscription management, background tasks, and social media integrations, offering a solid foundation for building modern, feature-rich SaaS products.  

---

## **Key Features**  

### **Authentication and User Management**  
- Full authentication system with support for signup, login, and password reset.  
- **Magic Link Login** powered by **django-seaman** for passwordless authentication.  
- JWT-based authentication powered by **Django REST Framework** and **Simple JWT**.  
- Profile management and user roles for granular access control.

### **Multi-Tenancy Support**  
- Built with **django-tenants** for seamless multi-tenancy.  
- Isolated tenant databases to ensure data separation and security.  
- Centralized configuration for managing multiple organizations.  

### **AI Integration**  
- AI-powered GitHub commit-to-post generator using **OpenAI**.  
- Automate and streamline content generation for social media and more.  

### **Subscription Management (Not Implemented Yet)**  
- Integrated with **Stripe** for subscription handling.  
- Support for one-time payments, recurring subscriptions, and invoices.  

### **Media Storage (Done on the frontend)**  
- Configured for media storage using **AWS S3** or **Cloudinary** for efficient asset management.  

### **Background Task Handling**  
- Task queue management using **Celery** and **Redis**.  
- Periodic task scheduling with **django-celery-beat**.  
- Background job handling with **django-background-tasks**.  

### **Notifications**  
- Real-time notifications to keep users updated on important events.  

### **Social Media Integration**  
- Post to **Twitter** directly from your SaaS product (in progress).  
- Post to **LinkedIn** directly from your SaaS product.

---

## **Tech Stack**  

### **Backend**  
- **Django** 5.1.4: Web framework for rapid development.  
- **Django REST Framework (DRF)**: For building RESTful APIs.  
- **Djoser**: Simplifies user authentication workflows.  
- **django-seaman**: Implements **Magic Link Authentication** for seamless login.  


### **Database**  
- **PostgreSQL**: Robust and scalable database, supporting multi-tenancy.  

### **Task Queue**  
- **Celery**: Distributed task queue for handling asynchronous tasks.  
- **Redis**: Fast, in-memory data store for caching and task queuing.  

### **Social Media APIs**  
- **requests_oauthlib**: Manage interactions with the Twitter API.  

### **Payments (Not Implemented yet)**  
- **Stripe**: Simplifies subscription and payment handling.  

---

## **Installation and Setup**  

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/brilliantmakanju/django_saas_starter_kit.git
   cd django_saas_starter_kit
   ```

2. **Set Up Environment Variables**  
   Create a `.env` file and add the following:  
   ```plaintext
    DEBUG=<true_or_false>
    DOMAIN=<your_domain>
    SITE_NAME=<your_site_name>
    DB_NAME=<your_db_name>
    SECRET_KEY=<your_secret_key>
    EMAIL_APP_USER_HOST=<your_email_user_host>
    DB_PASSWORD=<your_db_password>
    DB_USERNAME=<your_db_username>
    NVIDIA_API_KEY=<your_nvidia_api_key>
    GOOGLE_OAUTH2_API_KEY=<your_google_oauth2_api_key>
    STRIPE_TEST_PUBLIC_KEY=<your_stripe_test_public_key>
    STRIPE_TEST_SECRET_KEY=<your_stripe_test_secret_key>
    TWITTER_API_KEY=<your_twitter_api_key>
    TWITTER_CLIENT_ID=<your_twitter_client_id>
    TWITTER_TOKEN_URL=<your_twitter_token_url>
    CLOUDINARY_API_KEY=<your_cloudinary_api_key>
    CLOUDINARY_API_SECRET=<your_cloudinary_api_secret>
    FRONTEND_DOMAIN=<your_frontend_domain>
    TWITTER_BEARER_TOKEN=<your_twitter_bearer_token>
    TWITTER_ACCESS_KEY=<your_twitter_access_key>
    TWITTER_REDIRECT_URI=<your_twitter_redirect_uri>
    DJANGO_FERNET_KEY=<your_django_fernet_key>
    DJSTRIPE_WEBHOOK_SECRET=<your_djstripe_webhook_secret>
    TWITTER_AUTH_URL=<your_twitter_auth_url>
    TWITTER_CLIENT_SECRET=<your_twitter_client_secret>
    TWITTER_ACCESS_SECRET_KEY=<your_twitter_access_secret_key>
    STRIPE_WEBHOOK_SECRET=<your_stripe_webhook_secret>
    DJANGO_PRODUCT_OWNER_EMAIL=<your_product_owner_email>
    EMAIL_APP_HOST_PASSWORD=<your_email_host_password>
    CLOUDINARY_CLOUD_NAME=<your_cloudinary_cloud_name>
    NVIDIA_AI_BASE_URL=https://integrate.api.nvidia.com/v1
   ```

3. **Install Dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

4. **Apply Database Migrations**  
   ```bash
   python manage.py migrate
   ```

5. **Run the Development Server**  
   ```bash
   python manage.py runserver
   ```

---

## **Usage**  

### **Authentication**  
- Sign up or log in using the provided endpoints or the UI.  

### **Tenant Management**  
- Create and manage organizations with isolated data storage.  

### **AI Integration**  
- Generate GitHub commits or social media posts using AI.  

### **Background Tasks**  
- Schedule tasks or manage periodic jobs via Celery and Redis.  

### **Social Media Posting**  
- Authorize the app to connect to your social media accounts.  
- Post content directly to **LinkedIn** (Twitter support coming soon).  

---

## **Packages and Libraries**  

Below is a list of the main packages used in the project:  

### **Backend Framework and API**  
- **Django**: High-level Python web framework.  
- **Django REST Framework**: Toolkit for building Web APIs.  
- **Djoser**: REST implementation for Django Auth.
- **django-seaman**: Implements **Magic Link Authentication**.  

### **Task Queue and Scheduler**  
- **Celery**: Distributed task queue.  
- **django-celery-beat**: Scheduler for periodic tasks.  
- **django-background-tasks**: Simple background job processing.  

### **Social Media and Authentication**  
- **requests_oauthlib**: Manage Twitter API integration.  

### **Payments and Subscriptions (Not Implemented yet)**  
- **Stripe**: Handles payments and subscription plans.  

### **Database and Multi-Tenancy**  
- **PostgreSQL**: Relational database.  
- **django-tenants**: Adds multi-tenancy to Django apps.  

---

## **Contributing**  

Contributions are welcome! If you have ideas, improvements, or bug fixes, feel free to open a pull request.  

---

## **License**  
This project is licensed under the [MIT License](LICENSE).  

---

This README is structured to give a clear understanding of the project's capabilities, installation steps, and key technologies used.
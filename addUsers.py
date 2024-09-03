"""
File : addUsers.py
Author : Amelia Goldsby
Date Created : 03/09/2024
Project : ISA Recommendation Website
Course : Software Engineering and Agile
         Level 5, QA 

Description : This file contains adding data to the tables on the Vercel Database. 
              It is ran through the terminal using python addUsers.py
"""
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import bcrypt
from app import app, db, User, Projections, hashPassword, calculateFutureValue, getRiskAer, calculateRiskRatingCount

# Initialize Flask application context
with app.app_context():
    try:
        # Check if any users exist in the database
        if User.query.first() is not None:
            print("Data already initialized.")
        else:
            # Define 2 admin users and 8 regular users
            admin_users = [
                {'username': 'admin1', 'password': 'admin_password1'},
                {'username': 'admin2', 'password': 'admin_password2'}
            ]
            regular_users = [
                {'username': f'user{i}', 'password': f'user{i}_password'} for i in range(1, 9)
            ]

            # Add users to the database
            for user_data in admin_users:
                if not User.query.filter_by(username=user_data['username']).first():
                    hashed_password = hashPassword(user_data['password'])
                    new_user = User(
                        username=user_data['username'],
                        password=hashed_password,
                        admin=True
                    )
                    db.session.add(new_user)

            for user_data in regular_users:
                if not User.query.filter_by(username=user_data['username']).first():
                    hashed_password = hashPassword(user_data['password'])
                    new_user = User(
                        username=user_data['username'],
                        password=hashed_password,
                        admin=False
                    )
                    db.session.add(new_user)

            db.session.commit()  # Commit users to the database

            # Retrieve all users from the database
            all_users = User.query.all()

            # Define values for projections
            deposit = 1000.0
            monthly_payment = 50.0
            years = 10

            # Add projections for each user
            for user in all_users:
                if not Projections.query.filter_by(userId=user.id).first():
                    # Calculate future value of savings
                    annual_aer = 0.0484  # Default AER
                    risk_aer = getRiskAer('medium')  # Example risk rating
                    
                    projection_amount = calculateFutureValue(deposit, monthly_payment, years, annual_aer)
                    projection_risk_amount = calculateFutureValue(deposit, monthly_payment, years, risk_aer)
                    
                    # Create new projection
                    projection = Projections(
                        deposit=deposit,
                        monthlyPayment=monthly_payment,
                        years=years,
                        savings=True,
                        highDebt=False,
                        changes=False,
                        riskRating='medium',
                        riskRatingCount=calculateRiskRatingCount('medium', 'veryComfortable', 'regularly'),
                        projectionAmount=projection_amount,
                        projectionRiskAmount=projection_risk_amount,
                        userId=user.id
                    )
                    db.session.add(projection)

            db.session.commit()  # Commit projections to the database

            print("Data initialization complete.")

    except IntegrityError:
        db.session.rollback()
        print("Error adding data. Some entries might already exist.")
    except Exception as e:
        db.session.rollback()
        print(f"An unexpected error occurred: {e}")

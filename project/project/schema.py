import graphene
from graphene_django import DjangoObjectType
from app.models import CustomUser
from graphql import GraphQLError
from graphql_jwt.shortcuts import get_token
from graphql_jwt.shortcuts import create_refresh_token
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
# from types import UserType
from django.contrib.auth.tokens import default_token_generator
# from django.utils.encoding import force_bytes
# from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .utils import send_otp_email, verify_otp,generate_otp
import graphql_jwt
# from django.contrib.auth import logout

class UserType(DjangoObjectType):
    class Meta:
        model = CustomUser
        fields = ("id", "username", "email","created_at")

class RegisterUser(graphene.Mutation):
    class Arguments:
        username = graphene.String(required=True)
        email = graphene.String(required=True)
        password = graphene.String(required=True)
        createdAt=graphene.DateTime(required=True)
        

    user = graphene.Field(UserType)
    token = graphene.String()

    def mutate(self, info, username, email, password,createdAt):
        user = CustomUser(username=username, email=email)
        user.set_password(password)
        user.created_at = createdAt
        user.save()
        token = get_token(user)
        
        return RegisterUser(user=user, token=token)

class LoginUser(graphene.Mutation):
    class Arguments:
        email = graphene.String(required=True)
        password = graphene.String(required=True)

    user = graphene.Field(UserType)
    token = graphene.String()
    refresh_token = graphene.String()

    def mutate(self, info, email, password):
        user = authenticate(info.context, username=email, password=password)
        if user is None:
            raise GraphQLError('Invalid credentials')
        token = get_token(user)
        refresh_token = create_refresh_token(user)

        return LoginUser(user=user, token=token, refresh_token=refresh_token)
    
class ChangePassword(graphene.Mutation):
    class Arguments:
        old_password = graphene.String(required=True)
        new_password = graphene.String(required=True)

    user = graphene.Field(UserType)
    # success = graphene.Boolean() 

    def mutate(self,info, old_password, new_password):
        user =info.context.user
        user1 = authenticate(username=user.username,password=old_password)
        if old_password is  None and new_password is  None :
            raise GraphQLError('empty old_password and new password')
        if user1 is None:
            raise GraphQLError('User not found')
        if old_password == new_password:
            raise GraphQLError('New password cannot be same as old password')

        user1.set_password(new_password)
        user1.save()
        return ChangePassword(user=user)
    
    
class ForgotPassword(graphene.Mutation):
    class Arguments:
        email = graphene.String(required=True)
        new_password = graphene.String(required=True)
        
    success = graphene.Boolean()

    def mutate(self, info, email, new_password):
        try:
            
            user = CustomUser.objects.get(email=email)
            if user is None:
                raise GraphQLError('User not found')
            user.set_password(new_password)
            user.save()
            return ForgotPassword(success=True)
        except User.DoesNotExist:
            return ForgotPassword(success=False)
        
class SendOtp(graphene.Mutation):
    class Arguments:
        email = graphene.String(required=True)

    success = graphene.Boolean()

    def mutate(self, info, email):
        try:
            user = CustomUser.objects.get(email=email)
            if user is None:
                raise GraphQLError('User not found')
            otp = generate_otp()
            send_otp_email(email, otp,user)
            return SendOtp(success=True)
        except CustomUser.DoesNotExist:
            return SendOtp(success=False)
        
class VerifyOtp(graphene.Mutation):
    class Arguments:
        email = graphene.String(required=True)
        otp = graphene.String(required=True)

    success = graphene.Boolean()

    def mutate(self, info, email, otp):
        try:
            user = CustomUser.objects.get(email=email)
            success = verify_otp(user, otp)
            return VerifyOtp(success=success)
        except User.DoesNotExist:
            return VerifyOtp(success=False)

class Logout(graphene.Mutation):
    success = graphene.Boolean()

    @staticmethod
    def mutate(root, info):
        info.context.user.jwt_token = None
        info.context.user.jwt_refresh_token = None 
        return Logout(success=True) 
      
class Mutation(graphene.ObjectType):
    register_user = RegisterUser.Field()
    login_user = LoginUser.Field()
    change_password = ChangePassword.Field()
    forgot_password = ForgotPassword.Field()
    send_otp = SendOtp.Field()
    verify_otp = VerifyOtp.Field()
    logout = Logout.Field()
    token_auth = graphql_jwt.ObtainJSONWebToken.Field()
    verify_token = graphql_jwt.Verify.Field()
    refresh_token = graphql_jwt.Refresh.Field()
    revoke_token = graphql_jwt.relay.Revoke.Field()  

class Query(graphene.ObjectType):
    me = graphene.Field(UserType)

    def resolve_me(self, info): 
        user = info.context.user
        if user.is_anonymous:
            raise GraphQLError('Not logged in')
        return user

schema = graphene.Schema(query=Query, mutation=Mutation)

from flask import Blueprint, render_template, request, redirect, url_for,flash
from flask_login import login_required, current_user
from . import adminRequired
from app.models import User
from sqlalchemy import or_ 

PER_PAGE = 10
admin = Blueprint('admin', __name__)  

@admin.route('/admin', methods=['GET', 'POST'])
@adminRequired
@login_required

def adminLandingPage():
     return render_template('admin/sysadmindash.html',user=current_user) 


@admin.route('/admin/viewProfiles', methods=['GET', 'POST'])
@adminRequired
@login_required

def adminViewProfiles():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '')

    query = User.query

    if search_query:
        search = f"%{search_query}%"
        query = query.filter(or_(User.username.ilike(search), User.email.ilike(search)))

    usersPaginated = query.order_by(User.username.asc()).paginate(page=page, per_page=PER_PAGE, error_out=False)

    userCount = query.filter_by(role='user').count()
    totalCount = query.count()
    adminCount = totalCount - userCount

    return render_template('admin/viewProfiles.html',
                           user=current_user,
                           users=usersPaginated.items,
                           pagination=usersPaginated,
                           totalCount=totalCount,
                           userCount=userCount,
                           adminCount=adminCount)

@admin.route('/admin/deleteUser/<username>', methods=['POST'])
@adminRequired
@login_required
def adminDeleteUser(username):
     userID = User.query.filter_by(username = username).first().id
     user = User.query.get_or_404(userID)
     if user.username == current_user.username: # self delete
          flash("ERROR: Unable to delete own account!","error")
          return redirect(url_for('admin.adminViewProfiles'))

     deleted = User.deleteUser(user)
     if deleted: 
          flash(f"User \"{user.username}\" has been deleted successfully","success")
     else: 
          flash(f"User \"{user.username}\" was NOT deleted due to an error","error")    
     return redirect(url_for('admin.adminViewProfiles'))

@admin.route('/admin/toggleUser/<username>', methods=['POST'])
@adminRequired
@login_required
def adminToggleUser(username):
    
     userID = User.query.filter_by(username = username).first().id
     
     user = User.query.get_or_404(userID)
     if user.role == 'superadmin':
          flash("ERROR: Superadmin CANNOT be downgraded","error")
          return redirect(url_for('admin.adminViewProfiles'))
     
     if user.username == current_user.username: # self delete
          flash("ERROR: Unable to downgrade own privileges","error")
          return redirect(url_for('admin.adminViewProfiles'))
     
     newRole = 'user'
     if user.role == 'user':
          newRole = 'admin'
     user.role = newRole
     updated = user.updateDetails()

     if updated: 
          flash(f"User \"{user.username}\"'s role has been changed to {newRole} successfully","success")
     else: 
          flash(f"User \"{user.username}\"'s role was NOT updated due to an error","error")    
     return redirect(url_for('admin.adminViewProfiles'))

from .db import User, Role
from flask import g, session, current_app
from enum import IntEnum


class UserAccess(IntEnum):
    ANONYMOUS = 1
    REGISTERED = 2
    EDITOR = 3
    ADMIN = 4
    OWNER = 5
    SUPER_ADMIN = 6


class SecAction:
    VIEW = 'view'
    NEW_NOTE = 'new_note'
    EDIT_NOTE = 'edit_note'
    ADD_COMMENT = 'add_comment'
    CYCLE_NOTE = 'cycle'
    EDIT_VECTORS = 'vectors'
    EDIT_PROJECT = 'edit_project'


DEFAULT_SECURITY = {
    SecAction.VIEW: UserAccess.ANONYMOUS,
    SecAction.NEW_NOTE: UserAccess.REGISTERED,
    SecAction.EDIT_NOTE: UserAccess.EDITOR,
    SecAction.ADD_COMMENT: UserAccess.REGISTERED,
    SecAction.CYCLE_NOTE: UserAccess.EDITOR,
    SecAction.EDIT_VECTORS: UserAccess.EDITOR,
    SecAction.EDIT_PROJECT: UserAccess.OWNER,
}


def get_user():
    if session.get('uid'):
        user = User.get_or_none(session['uid'])
        if user:
            return user
        del session['uid']
    return None


def get_access(project=None):
    if not g.user:
        return UserAccess.ANONYMOUS
    if 'access' in g:
        return g.access

    access = None
    super_admins = current_app.config.get('ADMINS', [])
    if g.user.id in super_admins:
        access = UserAccess.SUPER_ADMIN
    elif project:
        if g.user == project.owner:
            access = UserAccess.OWNER
        else:
            role = Role.get_or_none(Role.user == g.user, Role.project == project)
            if role:
                if role.is_admin:
                    access = UserAccess.ADMIN
                else:
                    access = UserAccess.EDITOR
    g.access = access or UserAccess.REGISTERED
    return g.access


def check_access(project, what):
    if not project.security:
        return DEFAULT_SECURITY[what] <= get_access(project)
    return project.security.get(what, DEFAULT_SECURITY[what]) <= get_access(project)

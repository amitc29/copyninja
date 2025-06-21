// import AnalyticsClient from '../services/AnalyticsClient.js';
import fetch from 'node-fetch';


class AnalyticController {
    analytics = new AnalyticsClient(config.zoho.zoho_client_id, config.zoho.zoho_client_secret, config.zoho.zoho_refresh_token)

    getOrg(req, res, next) {
        return this.analytics.getOrgInstance()
    }

    getWorkspaces(req, res, next) {
        return this.analytics.getWorkspaces()
    }
    getSharedWorkspaces(req, res, next) {
        return this.analytics.getSharedWorkspaces()
    }
    getRecentViews(req, res, next) {
        return this.analytics.getRecentViews()
    }
    getDashboards(req, res, next) {
        return this.analytics.getDashboards()
    }
    getOwnedDashboards(req, res, next) {
        return this.analytics.getOwnedDashboards()
    }
    getSharedDashboards(req, res, next) {
        return this.analytics.getSharedDashboards()
    }
    getWorkspaceDetails(req, res, next) {
        return this.analytics.getWorkspaceDetails(workspaceId)
    }
    getViewDetails(req, res, next) {
        return this.analytics.getViewDetails(viewId, config = {})
    }
    getOrgInstance(req, res, next) {
        return this.analytics.getOrgInstance(orgId)
    }
    getWorkspaceInstance(req, res, next) {
        return this.analytics.getWorkspaceInstance(orgId, workspaceId)
    }
    getViewInstance(req, res, next) {
        return this.analytics.getViewInstance(orgId, workspaceId, viewId)
    }
    getBulkInstance(req, res, next) {
        return this.analytics.getBulkInstance(orgId, workspaceId)
    }
    handleBatchImportRequest() {
        return this.analytics.handleBatchImportRequest(uriPath, config, header, filePath, batchSize)
    }
    sendBatchImportRequest(req, res, next) {
        return this.analytics.sendBatchImportRequest(url, header, batch)
    }
    handleImportRequest(req, res, next) {
        return this.analytics.handleImportRequest(uriPath, config, header, filePath, data = null)
    }
    sendImportRequest(req, res, next) {
        return this.analytics.sendImportRequest(url, header, data)
    }
    handleExportRequest(req, res, next) {
        return this.analytics.handleExportRequest(uriPath, filePath, config, header)
    }
    sendExportRequest(req, res, next) {
        return this.analytics.sendExportRequest(uriPath, filePath, config, header = {})
    }
    handleV2Request(req, res, next) {
        return this.analytics.handleV2Request(uriPath, method, config, header, isExportReq = false)
    }
    sendV2Request(req, res, next) {
        return this.analytics.sendV2Request(uriPath, reqMethod, config, header = {}, isExportReq = false)
    }
    getOauth(req, res, next) {
        return this.analytics.getOauth()
    }
}

class OrgAPIController {
    createWorkspace(req, res, next) {
        return this.analytics.createWorkspace(workspaceName, config = {})
    }
    getAdmins(req, res, next) {
        return this.analytics.getAdmins(config = {})
    }
    getSubscriptionDetails(req, res, next) {
        return this.analytics.getSubscriptionDetails()
    }
    getResourceDetails(req, res, next) {
        return this.analytics.getResourceDetails()
    }
    getUsers(req, res, next) {
        return this.analytics.getUsers()
    }
    addUsers(req, res, next) {
        return this.analytics.addUsers(emailIds, config = {})
    }
    removeUsers(req, res, next) {
        return this.analytics.removeUsers(emailIds, config = {})
    }
    activateUsers(req, res, next) {
        return this.analytics.activateUsers(emailIds, config = {})
    }
    deActivateUsers(req, res, next) {
        return this.analytics.deActivateUsers(emailIds, config = {})
    }
    changeUserRole(req, res, next) {
        return this.analytics.changeUserRole(emailIds, role, config = {})
    }
    getMetaDetails(req, res, next) {
        return this.analytics.getMetaDetails(workspaceName, viewName = null, config = {})
    }
}

class WorkspaceAPIController {
    copy(req, res, next) {
        return this.analytics.copy(workspaceName, config = {}, destOrgId = null)
    }
    rename(req, res, next) {
        return this.analytics.rename(workspaceName, config = {})
    }
    delete(req, res,) {
        return this.analytics.delete(config = {})
    }
    createTable(req, res, next) {
        return this.analytics.createTable(tableDesign, config = {})
    }
    createQueryTable(req, res, next) {
        return this.analytics.createQueryTable(sqlQuery, queryTableName, config = {})
    }
    editQueryTable(req, res, next) {
        return this.analytics.editQueryTable(viewId, sqlQuery, config = {})
    }
    getSecretKey(req, res, next) {
        return this.analytics.getSecretKey(config = {})
    }
    addFavorite(req, res, next) {
        return this.analytics.addFavorite(config = {})
    }
    removeFavorite(req, res, next) {
        return this.analytics.removeFavorite(config = {})
    }
    addDefault(req, res, next) {
        return this.analytics.addDefault(config = {})
    }
    removeDefault(req, res, next) {
        return this.analytics.removeDefault(config = {})
    }
    getAdmins(req, res, next) {
        return this.analytics.getAdmins(config = {})
    }
    addAdmins(req, res, next) {
        return this.analytics.addAdmins(emailIds, config = {})
    }
    removeAdmins(req, res, next) {
        return this.analytics.removeAdmins(emailIds, config = {})
    }
    getShareInfo(req, res, next) {
        return this.analytics.getShareInfo()
    }
    shareViews(req, res, next) {
        return this.analytics.shareViews(viewIds, emailIds, permissions, config = {})
    }
    removeShare(req, res, next) {
        return this.analytics.removeShare(viewIds, emailIds, config = {})
    }
    getSharedDetailsForViews(req, res, next) {
        return this.analytics.getSharedDetailsForViews(viewIds)
    }
    getFolders(req, res, next) {
        return this.analytics.getFolders()
    }
    createFolder(req, res, next) {
        return this.analytics.createFolder(folderName, config = {})
    }
    getViews(req, res, next) {
        return this.analytics.getViews(config = {})
    }
    copyViews(req, res, next) {
        return this.analytics.copyViews(viewIds, destWorkspaceId, config = {}, destOrgId = null)
    }
    enableDomainAccess(req, res, next) {
        return this.analytics.enableDomainAccess()
    }
    disableDomainAccess(req, res, next) {
        return this.analytics.disableDomainAccess()
    }
    renameFolder(req, res, next) {
        return this.analytics.renameFolder(folderId, newFolderName, config = {})
    }
    deleteFolder(req, res, next) {
        return this.analytics.deleteFolder(folderId)
    }
    getGroups(req, res, next) {
        return this.analytics.getGroups()
    }
    getGroupDetails(req, res, next) {
        return this.analytics.getGroupDetails(groupId)
    }
    createGroup(req, res, next) {
        return this.analytics.createGroup(groupName, emailIds, config = {})
    }
    renameGroup(req, res, next) {
        return this.analytics.renameGroup(groupId, newGroupName, config = {})
    }
    addGroupMembers(req, res, next) {
        return this.analytics.addGroupMembers(groupId, emailIds, config = {})
    }
    removeGroupMembers(req, res, next) {
        return this.analytics.removeGroupMembers(groupId, emailIds, config = {})
    }
}
import { client as sql } from './sql/client.js';

export const ACCOUNTS_TABLE = 'gp_accounts';
export const ORG_MEMBERS_TABLE = 'gp_org_members';
export const USERS_TABLE = 'directus_users';
const APPROVING_ROLES = [ 'admin', 'member' ];

export const getUserAccountId = async (userId: string): Promise<string | null> => {
	const account = await sql(ACCOUNTS_TABLE).where({ user: userId }).first<{ id: string } | undefined>('id');
	return account?.id ?? null;
};

// Is it a personal account of the user, or an org account where their role is 'admin' or 'member'?
export const isAccountAvailable = async (accountId: string, userId: string): Promise<boolean> => {
	const account = await sql(ACCOUNTS_TABLE)
		.leftJoin(ORG_MEMBERS_TABLE, function () {
			this.on(`${ORG_MEMBERS_TABLE}.org`, `${ACCOUNTS_TABLE}.org`)
				.andOnVal(`${ORG_MEMBERS_TABLE}.user`, '=', userId)
				.andOnIn(`${ORG_MEMBERS_TABLE}.role`, APPROVING_ROLES);
		})
		.where(`${ACCOUNTS_TABLE}.id`, accountId)
		.where(function () {
			this.where(`${ACCOUNTS_TABLE}.user`, userId).orWhereNotNull(`${ORG_MEMBERS_TABLE}.id`);
		})
		.first<{ id: string } | undefined>(`${ACCOUNTS_TABLE}.id`);

	return Boolean(account);
};

// Does the user have an org to act for? If not, the approval screen has nothing to ask about and may be skipped.
// It lists the orgs the user picked in the dashboard, so this has to look at the same list.
export const hasSelectableOrgs = async (userId: string): Promise<boolean> => {
	const membership = await sql(ORG_MEMBERS_TABLE)
		.join(USERS_TABLE, `${USERS_TABLE}.id`, `${ORG_MEMBERS_TABLE}.user`)
		.where(`${ORG_MEMBERS_TABLE}.user`, userId)
		.whereIn(`${ORG_MEMBERS_TABLE}.role`, APPROVING_ROLES)
		.whereRaw(`JSON_CONTAINS(${USERS_TABLE}.selected_orgs, JSON_QUOTE(${ORG_MEMBERS_TABLE}.org))`)
		.first<{ id: string } | undefined>(`${ORG_MEMBERS_TABLE}.id`);

	return Boolean(membership);
};

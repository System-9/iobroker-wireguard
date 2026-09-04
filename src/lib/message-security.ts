/**
 * Only ioBroker Admin instances may receive newly generated private keys.
 *
 * @param sender
 */
export function isAuthorizedAdminSender(sender: string): boolean {
    return /^(?:system\.adapter\.)?admin\.\d+$/.test(sender);
}

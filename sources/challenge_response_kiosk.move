/*
MIT License

Author Tobias Rothmann

Copyright (c) 2023 TUM Blockchain Club

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/*
SUI Kiosk allows to enforce policies on trades, we lift this mechanism up to a challenge-reponse protocol, with 
the challenge_response_kiosk.  
Thus enabling ownership-secure trade for protocols, that rely on verification proofs.
We achieve this with only minor changes on the interface: 
The buyer calls "purchase", as usual, however now includes a challenge (mostly random bytes), waits until the Kiosks has automatically 
verfied the seller's verification proof and sent the object of desire to him.
The seller, gained an additional step, the "submit_sig", aka submit Signiture, function. It's purpose is to proof the challenge 
sent by the buyer. The Kiosk automatically checks wether the submitted signature from the seller actually solve's the challenge and 
if so completes the purchase, otherwise (if the signature is invalid) the kiosk pay back the buyer funds.
*/
module challenge_response_kiosk::challenge_response_kiosk {
    use std::option::{Self, Option, none, some};
    use sui::tx_context::{TxContext, sender};
    use sui::bag::{Self};
    use sui::kiosk::{Self, Kiosk, KioskOwnerCap, PurchaseCap, Borrow};
    use sui::kiosk_extension::{Self};
    use sui::object::{Self, ID, UID};
    use sui::transfer_policy::{TransferPolicy, TransferRequest};
    use sui::balance::{Balance};
    use sui::coin::{Coin};
    use sui::sui::SUI;
    use sui::event;
    use verificator::verificator::verify_sig;
    use sui::transfer;

    const ENotBuyer: u64 = 0;

    const EItemReserved: u64 = 1;

    struct EXT has drop {}

    struct SignChallenge has copy, drop {
        id: ID,
        rand: vector<u8>,
        buyer: address
    }

    struct SignChallengeWithdrawn has copy, drop {
        id: ID,
        buyer: address
    }

    struct BuyerPackage<T: key + store> has store {
        challenge: vector<u8>,
        pk: vector<u8>,
        coins: Coin<SUI>,
        buyer: address,
        cap: Option<PurchaseCap<T>>
    }

    //create a new Challenge-Response-Kiosk
    public fun new(ctx: &mut TxContext): (Kiosk, KioskOwnerCap){
        let (k, k_cap) = kiosk::new(ctx);
        kiosk::set_allow_extensions(&mut k, &k_cap, true);
        kiosk_extension::add(EXT {}, &mut k, &k_cap, 00, ctx);    
        (k,k_cap)
    }

    fun init(ctx : &mut TxContext) {
        let (k, k_cap) = kiosk::new(ctx);
        kiosk::set_allow_extensions(&mut k, &k_cap, true);
        kiosk_extension::add(EXT {}, &mut k, &k_cap, 00, ctx);
        transfer::public_transfer(k, sender(ctx));
        transfer::public_transfer(k_cap, sender(ctx))
    }

    //==altered functions==
    /*After the creation of the kiosk, we introduce the new functionallites in the "altered" functions, which replace their 
    counter-parts in the "normal" SUI Kiosk
    */

    /**
        This function is to be called only by the owner (who sells in the kiosk), which is why it 
        asks for the Owner Cap. 
        Its purpose is to verify that the owner(seller) has really solved the challenge of the buyer. 
        If the challenge was solved, the trade is automatically processed by the kiosk (the buyer get's his object of desire and 
        the owner his payment (coins)). If the challenge was not solved, the buyer gets back his coins and the trade is aborted.
    */
    public fun submit_sig<T: key + store>(self: &mut Kiosk, _cap: &KioskOwnerCap, sig: vector<u8>, sign_challenge: SignChallenge) 
        : (Option<T>,Option<TransferRequest<T>>){
        let ext_bag = kiosk_extension::storage_mut<EXT>(EXT {}, self);
        let BuyerPackage<T> {challenge, pk, coins, buyer, cap} = bag::remove(ext_bag, sign_challenge.id);
        if (verify_sig(pk, sig, challenge)) {
            if (option::is_none<PurchaseCap<T>>(&cap)) {
                option::destroy_none<PurchaseCap<T>>(cap);
                let (t,tr) = kiosk::purchase<T>(self, sign_challenge.id, coins);
                (some(t) ,some(tr))
            } else {
                let p_cap = option::destroy_some<PurchaseCap<T>>( cap);
                let (t,tr) = kiosk::purchase_with_cap<T>(self, p_cap, coins);
                (some(t) ,some(tr))
            }
        } else {
            if (option::is_none<PurchaseCap<T>>(&cap)) {
                option::destroy_none<PurchaseCap<T>>(cap);
            } else {
                let p_cap = option::destroy_some<PurchaseCap<T>>( cap);
                transfer::public_transfer(p_cap, buyer);
            };
            transfer::public_transfer(coins, buyer);
            (none(), none())
        }
    }


    /**
        The normal purchase function from SUI Kiosk, except that it requires a challenge (random bytes) as an additional argument 
        and does not process the trade immediatly, but instead sends a challenge to the owner to solve (e.g. to proof his eligibillity).
        The purchase (as long as the trade has not been processed) can always be withdrawn with the pull_out function, hence the buyer's 
        coins are never locked.
    */
    public fun purchase<T: store+key>(rand: vector<u8>, 
        self: &mut Kiosk, id: ID, pk: vector<u8>, payment: Coin<SUI>, ctx: &mut TxContext
    ){
        let ext_bag = kiosk_extension::storage_mut<EXT>(EXT {}, self);
        let value_at_id = bag::borrow<ID, Option<BuyerPackage<T>>>(ext_bag, id);
        assert!(option::is_none(value_at_id), EItemReserved);
        bag::add(ext_bag, id, BuyerPackage<T> {challenge: rand, pk, coins: payment, buyer: sender(ctx), cap : none()});
        event::emit(SignChallenge {rand, id, buyer:sender(ctx)})
    }

    /**
        list function extended to hold a entry for every item in the Kiosk, with the first intersted buyer's details 
        (challenge, address, coins and pk of the object of desire).
    */
    public fun list<T: key + store>(
        self: &mut Kiosk, cap: &KioskOwnerCap, id: ID, price: u64
    ) {
        kiosk::list<T>(self, cap, id, price);
        let ext_bag = kiosk_extension::storage_mut<EXT>(EXT {}, self);
        bag::add(ext_bag, id, (none() : Option<BuyerPackage<T>>));
    }

    //place is unaltered
    public fun place<T: key + store>(
        self: &mut Kiosk, cap: &KioskOwnerCap, item: T
    ) {
        kiosk::place<T>(self, cap, item)
    }

    //place and list altered to use the new list definition.
    public fun place_and_list<T: key + store>(
        self: &mut Kiosk, cap: &KioskOwnerCap, item: T, price: u64 
    ) {
        let id = object::id(&item);
        place(self, cap, item);
        list<T>(self, cap, id, price)
    }

    /**
        pull_out from a deal (buyer side), withdraws the challenge and returns the funds to the buyer 
        (as long as the trade has not been processed). Makes the item again purchasable by other interested buyers. 
    */
    public fun pull_out<T: key + store>(self: &mut Kiosk, id: ID, ctx: &mut TxContext) {
        let ext_bag = kiosk_extension::storage_mut<EXT>(EXT {}, self);
        let BuyerPackage<T> {challenge:_, pk:_, coins, buyer, cap} = bag::remove(ext_bag, id);
        assert!(sender(ctx) == buyer, ENotBuyer);
        transfer::public_transfer(coins, buyer);
        event::emit(SignChallengeWithdrawn {id, buyer})
        // TODO return cap to sender if exists
    }

    /**
        serves the same purpose as delist in the classical kiosk, but also resolves 
        any payments from buyers who challenged the seller (i.e. transfers funds back to buyer and withdraws challenge).
    */ 
    public fun delist<T: key + store>(
        self: &mut Kiosk, cap: &KioskOwnerCap, id: ID
    ) {
        let ext_bag = kiosk_extension::storage_mut<EXT>(EXT {}, self);
        let BuyerPackage<T> {challenge:_, pk:_, coins, buyer, cap : cap_opt} = bag::remove(ext_bag, id);
        transfer::public_transfer(coins, buyer);
        kiosk::delist<T>(self,cap,id)
    }

    /**
        serves the same purpose as take in the classical kiosk, but also resolves 
        any payments from buyers who challenged the seller (i.e. transfers funds back to buyer and withdraws challenge).
    */ 
    public fun take<T: key + store>(
        self: &mut Kiosk, cap: &KioskOwnerCap, id: ID
    ): T {
        let ext_bag = kiosk_extension::storage_mut<EXT>(EXT {}, self);
        let BuyerPackage<T> {challenge:_, pk:_, coins, buyer, cap: purchase_cap} = bag::remove(ext_bag, id);
        transfer::public_transfer(coins, buyer);
        kiosk::take<T>(self, cap, id)
    }

    /// checkn wether an item is purchasable (i.e. listed and not already challenged by another buyer).
    public fun is_purchasable<T:key + store>(self: &Kiosk, id: ID): bool {
        let ext_bag = kiosk_extension::storage<EXT>(EXT {}, self);
        let value_at_id = bag::borrow<ID, Option<BuyerPackage<T>>>(ext_bag, id);
        is_listed(self, id) && option::is_none(value_at_id)
    }

    //== unaltered still good kiosk functions==

    public fun close_and_withdraw(
        self: Kiosk, cap: KioskOwnerCap, ctx: &mut TxContext
    ): Coin<SUI> {
        kiosk::close_and_withdraw(self, cap, ctx)
    }
    
    public fun set_owner(
        self: &mut Kiosk, cap: &KioskOwnerCap, ctx: &TxContext
    ) {
        kiosk::set_owner(self, cap, ctx)
    }

    public fun set_owner_custom(
        self: &mut Kiosk, cap: &KioskOwnerCap, owner: address
    ) {
        kiosk::set_owner_custom(self, cap, owner)
    }

    public fun lock<T: key + store>(
        self: &mut Kiosk, cap: &KioskOwnerCap, _policy: &TransferPolicy<T>, item: T
    ) {
        kiosk::lock<T>(self, cap, _policy, item)
    }

    public fun has_item(self: &Kiosk, id: ID): bool {
        kiosk::has_item(self, id)
    }

    /// Check whether the `item` is present in the `Kiosk` and has type T.
    public fun has_item_with_type<T: key + store>(self: &Kiosk, id: ID): bool {
        kiosk::has_item_with_type<T>(self,id)
    }

    /// Check whether an item with the `id` is locked in the `Kiosk`. Meaning
    /// that the only two actions that can be performed on it are `list` and
    /// `list_with_purchase_cap`, it cannot be `take`n out of the `Kiosk`.
    public fun is_locked(self: &Kiosk, id: ID): bool {
        kiosk::is_locked(self, id)
    }

    /// Check whether an `item` is listed (exclusively or non exclusively).
    public fun is_listed(self: &Kiosk, id: ID): bool {
        kiosk::is_listed(self, id)
    }

    /// Check whether there's a `PurchaseCap` issued for an item.
    public fun is_listed_exclusively(self: &Kiosk, id: ID): bool {
        kiosk::is_listed_exclusively(self,id)
    }

    /// Check whether the `KioskOwnerCap` matches the `Kiosk`.
    public fun has_access(self: &mut Kiosk, cap: &KioskOwnerCap): bool {
        kiosk::has_access(self,cap)
    }

    /// Access the `UID` using the `KioskOwnerCap`.
    public fun uid_mut_as_owner(
        self: &mut Kiosk, cap: &KioskOwnerCap
    ): &mut UID {
        kiosk::uid_mut_as_owner(self,cap)
    }

    /// Get the immutable `UID` for dynamic field access.
    /// Always enabled.
    ///
    /// Given the &UID can be used for reading keys and authorization,
    /// its access
    public fun uid(self: &Kiosk): &UID {
        kiosk::uid(self)
    }

    /// Get the mutable `UID` for dynamic field access and extensions.
    /// Aborts if `allow_extensions` set to `false`.
    public fun uid_mut(self: &mut Kiosk): &mut UID {
        kiosk::uid_mut(self)
    }

    /// Get the owner of the Kiosk.
    public fun owner(self: &Kiosk): address {
        kiosk::owner(self)
    }

    /// Get the number of items stored in a Kiosk.
    public fun item_count(self: &Kiosk): u32 {
        kiosk::item_count(self)
    }

    /// Get the amount of profits collected by selling items.
    public fun profits_amount(self: &Kiosk): u64 {
        kiosk::profits_amount(self)
    }

    /// Get mutable access to `profits` - owner only action.
    public fun profits_mut(self: &mut Kiosk, cap: &KioskOwnerCap): &mut Balance<SUI> {
        kiosk::profits_mut(self,cap)
    }

    // === Item borrowing ===

    /// Immutably borrow an item from the `Kiosk`. Any item can be `borrow`ed
    /// at any time.
    public fun borrow<T: key + store>(
        self: &Kiosk, cap: &KioskOwnerCap, id: ID
    ): &T {
        kiosk::borrow<T>(self,cap,id)
    }

    /// Mutably borrow an item from the `Kiosk`.
    /// Item can be `borrow_mut`ed only if it's not `is_listed`.
    public fun borrow_mut<T: key + store>(
        self: &mut Kiosk, cap: &KioskOwnerCap, id: ID
    ): &mut T {
        kiosk::borrow_mut<T>(self,cap,id)
    }

    /// Take the item from the `Kiosk` with a guarantee that it will be returned.
    /// Item can be `borrow_val`-ed only if it's not `is_listed`.
    public fun borrow_val<T: key + store>(
        self: &mut Kiosk, cap: &KioskOwnerCap, id: ID
    ): (T, Borrow) {
        kiosk::borrow_val<T>(self,cap,id)
    }

    /// Return the borrowed item to the `Kiosk`. This method cannot be avoided
    /// if `borrow_val` is used.
    public fun return_val<T: key + store>(
        self: &mut Kiosk, item: T, borrow: Borrow
    ) {
        kiosk::return_val<T>(self,item,borrow)
    }

    // === KioskOwnerCap fields access ===

    /// Get the `for` field of the `KioskOwnerCap`.
    public fun kiosk_owner_cap_for(cap: &KioskOwnerCap): ID {
        kiosk::kiosk_owner_cap_for(cap)
    }

    // === PurchaseCap fields access ===

    /// Get the `kiosk_id` from the `PurchaseCap`.
    public fun purchase_cap_kiosk<T: key + store>(self: &PurchaseCap<T>): ID {
        kiosk::purchase_cap_kiosk<T>(self)
    }

    /// Get the `Item_id` from the `PurchaseCap`.
    public fun purchase_cap_item<T: key + store>(self: &PurchaseCap<T>): ID {
        kiosk::purchase_cap_item<T>(self)
    }

    /// Get the `min_price` from the `PurchaseCap`.
    public fun purchase_cap_min_price<T: key + store>(self: &PurchaseCap<T>): u64 {
        kiosk::purchase_cap_min_price<T>(self)
    }

    public fun withdraw(
        self: &mut Kiosk, cap: &KioskOwnerCap, amount: Option<u64>, ctx: &mut TxContext
    ): Coin<SUI> {
        kiosk::withdraw(self, cap,amount,ctx)
    }

    //==unaltered kiosk functions that are TODO==

    public fun return_purchase_cap<T: key + store>(
        self: &mut Kiosk, purchase_cap: kiosk::PurchaseCap<T>
    ) {
        //TODO
        kiosk::return_purchase_cap<T>(self, purchase_cap)
    }

    public fun list_with_purchase_cap<T: key + store>(
        self: &mut Kiosk, cap: &KioskOwnerCap, id: ID, min_price: u64, ctx: &mut TxContext
    ): kiosk::PurchaseCap<T> {
        let pc = kiosk::list_with_purchase_cap<T>(self,cap,id,min_price,ctx);
        let ext_bag = kiosk_extension::storage_mut<EXT>(EXT {}, self);
        bag::add(ext_bag, id, (none() : Option<BuyerPackage<T>>));
        pc
    }

    public fun purchase_with_cap<T: key + store>(
        self: &mut Kiosk, purchase_cap: kiosk::PurchaseCap<T>, payment: Coin<SUI>
    ): (T, TransferRequest<T>) {
        //TODO
        kiosk::purchase_with_cap<T>(self, purchase_cap, payment)
    }
}
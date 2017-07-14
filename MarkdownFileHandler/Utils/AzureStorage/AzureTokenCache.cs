/*
 * Markdown File Handler - Sample Code
 * Copyright (c) Microsoft Corporation
 * All rights reserved. 
 * 
 * MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of 
 * this software and associated documentation files (the ""Software""), to deal in 
 * the Software without restriction, including without limitation the rights to use, 
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */




namespace MarkdownFileHandler.Utils
{
    using System;
    using Microsoft.Identity.Client;
    using Microsoft.WindowsAzure.Storage.Table;
    using System.Threading;

    public class MSALPersistentTokenCache
    {
        private static ReaderWriterLockSlim SessionLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);

        /// <summary>
        /// Unique identifier for the user this persistent token cache is assocaited with
        /// </summary>
        public string UserId { get; set; }

        /// <summary>
        /// Context for our Azure table operations
        /// </summary>
        private AzureTableContext tables = new AzureTableContext();

        /// <summary>
        /// Cached instance of the real TokenCache object
        /// </summary>
        TokenCache cache = new TokenCache();

        /// <summary>
        /// Cached instance of our Azure table persisted object
        /// </summary>
        AzureTokenCacheEntity persistedCacheEntity = null;

        public MSALPersistentTokenCache(string userId)
        {
            this.UserId = userId;

            this.Load();
        }

        public TokenCache GetMsalCacheInstance()
        {
            cache.SetBeforeAccess(BeforeAccessNotification);
            cache.SetAfterAccess(AfterAccessNotification);
            Load();
            return cache;
        }

        public void Load()
        {
            SessionLock.EnterReadLock();

            var cacheData = ReadPersistedEntry();
            cache.Deserialize(cacheData?.CacheBits);

            SessionLock.ExitReadLock();
        }

        /// <summary>
        /// Reads the persisted token cache entity from Azure table storage
        /// </summary>
        /// <returns></returns>
        private AzureTokenCacheEntity ReadPersistedEntry()
        {
            try
            {
                TableOperation retrieve = TableOperation.Retrieve<AzureTokenCacheEntity>(AzureTokenCacheEntity.PartitionKeyValue, UserId);
                TableResult results = tables.UserTokenCacheTable.Execute(retrieve);

                var persistedEntry = (AzureTokenCacheEntity)results.Result;
                return persistedEntry;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"ReadPersistedEntry: Exception reading from Azure table storage: {ex.Message}.");
                return null;
            }
        }

        /// <summary>
        /// Writes the cacheBits data back to the Azure table store
        /// </summary>
        /// <param name="cacheBits"></param>
        /// <param name="entity"></param>
        private AzureTokenCacheEntity WritePersistedEntry(byte[] cacheBits, AzureTokenCacheEntity entity)
        {
            if (entity == null)
            {
                entity = new AzureTokenCacheEntity();
                entity.RowKey = this.UserId;
            }
            
            entity.CacheBits = cacheBits;
            entity.LastWrite = DateTime.Now;

            TableOperation insert = TableOperation.InsertOrReplace(entity);
            tables.UserTokenCacheTable.Execute(insert);

            return entity;
        }

        public void Persist()
        {
            SessionLock.EnterWriteLock();

            // Optimistically set HasStateChanged to false. We need to do it early to avoid losing changes made by a concurrent thread.
            cache.HasStateChanged = false;

            // Reflect changes in the persistent store
            this.persistedCacheEntity = WritePersistedEntry(cache.Serialize(), this.persistedCacheEntity);

            SessionLock.ExitWriteLock();
        }

        // Triggered right before MSAL needs to access the cache.
        // Reload the cache from the persistent store in case it changed since the last access.
        void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            Load();
        }

        // Triggered right after MSAL accessed the cache.
        void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (cache.HasStateChanged)
            {
                Persist();
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using API.FornitureStore.Data;
using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Share;

namespace API.FurnitoreStore.Application.Services
{
    public class ProductsService : IProductsService
    {
        private readonly ApplicationDbContext _context;

        public ProductsService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task CreateAsync(Product product)
        {
            try
            {
                await _context.Products.AddAsync(product);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                throw new Exception("Error creating product", ex);
            }
        }

        public async Task DeleteAsync(int id)
        {
            try
            {
                var existing = await _context.Products.FindAsync(id);
                if (existing == null)
                    throw new Exception("Product not found.");

                _context.Products.Remove(existing);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                throw new Exception("Error deleting product", ex);
            }
        }

        public async Task<IEnumerable<Product>> GetAllAsync()
        {
            try
            {
                return await _context.Products.ToListAsync();
            }
            catch (Exception ex)
            {
                throw new Exception("Error retrieving products", ex);
            }
        }

        public async Task<Product?> GetByIdAsync(int id)
        {
            try
            {
                return await _context.Products.FindAsync(id);
            }
            catch (Exception ex)
            {
                throw new Exception("Error retrieving product", ex);
            }
        }

        public async Task UpdateAsync(Product product)
        {
            try
            {
                var existing = await _context.Products.FindAsync(product.Id);
                if (existing == null)
                    throw new Exception("Product not found.");

                existing.Name = product.Name;
                existing.Price = product.Price;
                existing.ProductCategoryId = product.ProductCategoryId;

                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                throw new Exception("Error updating product", ex);
            }
        }
    }
}
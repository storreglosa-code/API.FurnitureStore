using API.FornitureStore.Data;
using API.FurnitoreStore.Application.Interfaces;
using API.FurnitoreStore.Share;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace API.FurnitoreStore.Application.Services
{
    public class ProductCategoriesService (ApplicationDbContext context): IProductCategoriesService
    {
        public async Task CreateAsync(ProductCategory productCategory)
        {
            try
            {
                await context.ProductCategories.AddAsync(productCategory);
                await context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                throw new Exception ("Error al crear Categoria" , ex);
            }
        }

        public Task DeleteAsync(int id)
        {
            throw new NotImplementedException();
        }

        public async Task<IEnumerable<ProductCategory>> GetAllAsync()
        {
            try
            {
                var productCategories = await context.ProductCategories
                                                     .AsNoTracking()
                                                     .ToListAsync();
                return productCategories;
            }
            catch (Exception ex)
            {

                throw new Exception ("Error al obtener información", ex);
            }
        }

        public async Task<ProductCategory> GetByIdAsync(int id)
        {
            try
            {
                ProductCategory? productCategory = await context.ProductCategories
                                                               .AsNoTracking()
                                                               .FirstOrDefaultAsync(pc => pc.Id == id);
                return productCategory;
            }
            catch (Exception ex)
            {
                throw new Exception("Error al obtener información", ex);
            }
        }

        public async Task UpdateAsync(ProductCategory productCategory)
        {
            try
            {
                var existingCategory = await context.ProductCategories.FindAsync(productCategory.Id);
                if (existingCategory == null)
                {
                    throw new Exception("La categoría del producto no existe.");
                }
                existingCategory.Name = productCategory.Name;

                await context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                throw new Exception("Error al actualizar Categoria", ex);
            }
        }
    }
}
